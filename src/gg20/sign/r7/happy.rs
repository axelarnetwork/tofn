use crate::{
    collections::{FillVecMap, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{
            paillier,
            zkp::{chaum_pedersen, pedersen},
        },
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{
            r7::{self, Bcast, BcastHappy, BcastSadType7, MtaWcPlaintext},
            Participants, SignShareId,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use tracing::{error, warn};

use super::super::{r1, r2, r3, r5, r6, r8, Peers, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R7Happy {
    pub(crate) secret_key_share: SecretKeyShare,
    pub(crate) msg_to_sign: Scalar,
    pub(crate) peers: Peers,
    pub(crate) participants: Participants,
    pub(crate) keygen_id: TypedUsize<KeygenShareId>,
    pub(crate) k_i: Scalar,
    pub(crate) k_i_randomness: paillier::Randomness,
    pub(crate) sigma_i: Scalar,
    pub(crate) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(crate) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub(crate) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(crate) R: ProjectivePoint,
    pub(crate) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(crate) r5p2ps: P2ps<SignShareId, r5::P2p>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R7Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        // check for complaints
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r6::Bcast::Sad(_)))
        {
            warn!(
                "peer {} says: received an R6 complaint from others while in happy path",
                sign_id,
            );

            return Box::new(r7::sad::R7Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                R: self.R,
                r5bcasts: self.r5bcasts,
                r5p2ps: self.r5p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in);
        }

        let mut faulters = FillVecMap::with_size(participants_count);

        let mut bcasts = FillVecMap::with_size(participants_count);

        // our check for 'type 5` error succeeded, so any peer broadcasting a failure is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::Happy(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r6::Bcast::SadType5(_) => {
                    warn!(
                        "peer {} says: peer {} broadcasted a 'type 5' failure",
                        sign_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
                r6::Bcast::Sad(_) => return Err(TofnFatal), // This should never occur at this stage
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.unwrap_all()?;

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    commit: &self.r3bcasts.get(sign_peer_id)?.T_i.unwrap(),
                },
                msg_g: bcast.S_i.unwrap(),
                g: &self.R,
            };

            if let Err(err) = pedersen::verify_wc(&peer_stmt, &bcast.S_i_proof_wc) {
                warn!(
                    "peer {} says: pedersen proof wc failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let S_i_sum = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.S_i.unwrap()
            });

        if &S_i_sum != self.secret_key_share.group().y().unwrap() {
            warn!("peer {} says: 'type 7' fault detected", sign_id);

            // recover encryption randomness for mu; need to decrypt again to do so
            let mta_wc_plaintexts = self.r2p2ps.map_to_me(sign_id, |p2p| {
                let (mu_plaintext, mu_randomness) = self
                    .secret_key_share
                    .share()
                    .dk()
                    .decrypt_with_randomness(&p2p.mu_ciphertext);

                MtaWcPlaintext {
                    mu_plaintext,
                    mu_randomness,
                }
            })?;

            let proof = chaum_pedersen::prove(
                &chaum_pedersen::Statement {
                    base1: &k256::ProjectivePoint::generator(),
                    base2: &self.R,
                    target1: &(k256::ProjectivePoint::generator() * self.sigma_i),
                    target2: bcasts_in.get(sign_id)?.S_i.unwrap(),
                },
                &chaum_pedersen::Witness {
                    scalar: &self.sigma_i,
                },
            );

            let bcast_out = serialize(&Bcast::SadType7(BcastSadType7 {
                k_i: self.k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                proof,
                mta_wc_plaintexts,
            }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r8::R8Type7 {
                    secret_key_share: self.secret_key_share,
                    peers: self.peers,
                    participants: self.participants,
                    keygen_id: self.keygen_id,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    R: self.R,
                    r6bcasts: bcasts_in,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                }),
                bcast_out,
            }));
        }

        // compute r, s_i
        // reference for r: https://docs.rs/k256/0.8.1/src/k256/ecdsa/sign.rs.html#223-225
        let r = k256::Scalar::from_bytes_reduced(
            self.R
                .to_affine()
                .to_encoded_point(true)
                .x()
                .ok_or_else(|| {
                    error!("Invalid R point");
                    TofnFatal
                })?,
        );

        let s_i = self.msg_to_sign * self.k_i + r * self.sigma_i;

        corrupt!(s_i, self.corrupt_s_i(info.share_id(), s_i));

        let bcast_out = serialize(&Bcast::Happy(BcastHappy { s_i: s_i.into() }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r8::R8Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                R: self.R,
                r,
                r5bcasts: self.r5bcasts,
                r6bcasts: bcasts_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::R7Happy;
    use crate::{
        collections::TypedUsize,
        gg20::sign::{
            malicious::{log_confess_info, Behaviour::*},
            SignShareId,
        },
    };

    impl R7Happy {
        pub fn corrupt_s_i(
            &self,
            me: TypedUsize<SignShareId>,
            mut s_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R7BadSI = self.behaviour {
                log_confess_info(me, &self.behaviour, "");
                s_i += k256::Scalar::one();
            }
            s_i
        }
    }
}
