use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{
            paillier,
            zkp::{chaum_pedersen, pedersen},
        },
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{
            r7::{self, Bcast, BcastHappy, BcastSadType7, MtaWcPlaintext},
            KeygenShareIds, SignShareId,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use tracing::{error, warn};

use super::super::{r1, r2, r3, r5, r6, r8, Peers};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(in super::super) struct R7Happy {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) msg_to_sign: Scalar,
    pub(in super::super) peers: Peers,
    pub(in super::super) participants: KeygenShareIds,
    pub(in super::super) keygen_id: TypedUsize<KeygenShareId>,
    pub(in super::super) k_i: Scalar,
    pub(in super::super) k_i_randomness: paillier::Randomness,
    pub(in super::super) sigma_i: Scalar,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: FullP2ps<SignShareId, r5::P2p>,

    #[cfg(feature = "malicious")]
    pub(in super::super) behaviour: Behaviour,
}

impl Executer for R7Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_share_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who did not send a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if bcasts_in
            .iter()
            .any(|(_, bcast_option)| matches!(bcast_option, Some(r6::Bcast::Sad(_))))
        {
            warn!(
                "peer {} says: received an R6 complaint from others while in happy path",
                my_share_id,
            );

            return Box::new(r7::sad::R7Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                R: self.R,
                r5bcasts: self.r5bcasts,
                r5p2ps: self.r5p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        let mut bcasts = info.new_fillvecmap();

        // our check for 'type 5` error succeeded, so any peer broadcasting a failure is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::Happy(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r6::Bcast::SadType5(_) => {
                    warn!(
                        "peer {} says: peer {} broadcasted a 'type 5' failure",
                        my_share_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
                r6::Bcast::Sad(_) => return Err(TofnFatal), // This should never occur at this stage
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.to_vecmap()?;

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    prover_id: sign_peer_id,
                    commit: self.r3bcasts.get(sign_peer_id)?.T_i.as_ref(),
                },
                msg_g: bcast.S_i.as_ref(),
                g: &self.R,
            };

            if !pedersen::verify_wc(peer_stmt, &bcast.S_i_proof_wc) {
                warn!(
                    "peer {} says: pedersen proof wc failed to verify for peer {}",
                    my_share_id, sign_peer_id,
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
                acc + bcast.S_i.as_ref()
            });

        if &S_i_sum != self.secret_key_share.group().y().as_ref() {
            warn!("peer {} says: 'type 7' fault detected", my_share_id);

            // recover encryption randomness for mu; need to decrypt again to do so
            let mta_wc_plaintexts = self.r2p2ps.map_to_me(my_share_id, |p2p| {
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
                    prover_id: my_share_id,
                    base1: &k256::ProjectivePoint::generator(),
                    base2: &self.R,
                    target1: &(k256::ProjectivePoint::generator() * self.sigma_i),
                    target2: bcasts_in.get(my_share_id)?.S_i.as_ref(),
                },
                &chaum_pedersen::Witness {
                    scalar: &self.sigma_i,
                },
            );

            let bcast_out = Some(serialize(&Bcast::SadType7(BcastSadType7 {
                k_i: self.k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                proof,
                mta_wc_plaintexts,
            }))?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r8::R8Type7 {
                    secret_key_share: self.secret_key_share,
                    peers: self.peers,
                    participants: self.participants,
                    keygen_id: self.keygen_id,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    R: self.R,
                    r6bcasts: bcasts_in,
                }),
                bcast_out,
                None,
            )));
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

        corrupt!(s_i, self.corrupt_s_i(my_share_id, s_i));

        let bcast_out = Some(serialize(&Bcast::Happy(BcastHappy { s_i: s_i.into() }))?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r8::R8Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                R: self.R,
                r,
                r5bcasts: self.r5bcasts,
                r6bcasts: bcasts_in,
            }),
            bcast_out,
            None,
        )))
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
            sign_id: TypedUsize<SignShareId>,
            mut s_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R7BadSI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                s_i += k256::Scalar::one();
            }
            s_i
        }
    }
}
