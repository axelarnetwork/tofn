use crate::{hash::Randomness, k256_serde, mta::Secret, paillier_k256, refactor::{collections::{FillHoleVecMap, FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap}, keygen::{KeygenPartyIndex, SecretKeyShare}, sdk::{
            api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
        }, sign::{r4, SignParticipantIndex}}, zkp::{chaum_pedersen_k256, pedersen_k256}};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::super::{r1, r2, r3, r5, r6, r8, Peers, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R7 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier_k256::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    // TODO: Remove these as needed
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub(crate) nu_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2pHappy>,
    pub r3bcasts: VecMap<SignParticipantIndex, r3::happy::Bcast>,
    pub r4bcasts: VecMap<SignParticipantIndex, r4::happy::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r5bcasts: VecMap<SignParticipantIndex, r5::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub s_i: k256_serde::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub k_i: k256_serde::Scalar,
    pub k_i_randomness: paillier_k256::Randomness,
    pub proof: chaum_pedersen_k256::Proof,
    pub mta_wc_plaintexts: HoleVecMap<SignParticipantIndex, MtaWcPlaintext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaWcPlaintext {
    // mu_plaintext instead of mu
    // because mu_plaintext may differ from mu
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting mu
    pub mu_plaintext: paillier_k256::Plaintext,
    pub mu_randomness: paillier_k256::Randomness,
}

impl bcast_only::Executer for R7 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r6::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut faulters = FillVecMap::with_size(participants_count);

        let mut bcasts = FillVecMap::with_size(participants_count);

        // our check for 'type 5` error succeeded, so any peer broadcasting a failure is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::Happy(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r6::Bcast::Sad(_) => {
                    warn!(
                        "peer {} says: peer {} broadcasted a 'type 5' failure",
                        sign_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.unwrap_all()?;

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement {
                    commit: &self.r3bcasts.get(sign_peer_id)?.T_i.unwrap(),
                },
                msg_g: bcast.S_i.unwrap(),
                g: &self.R,
            };

            if let Err(err) = pedersen_k256::verify_wc(&peer_stmt, &bcast.S_i_proof_wc) {
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

            let mut mta_wc_plaintexts = FillHoleVecMap::with_size(participants_count, sign_id)?;

            for (sign_peer_id, _) in &self.peers {
                let r2p2p = self.r2p2ps.get(sign_peer_id, sign_id)?;

                // recover encryption randomness for mu; need to decrypt again to do so
                let (mu_plaintext, mu_randomness) = self
                    .secret_key_share
                    .share()
                    .dk()
                    .decrypt_with_randomness(&r2p2p.mu_ciphertext);

                let mta_wc_plaintext = MtaWcPlaintext {
                    mu_plaintext,
                    mu_randomness,
                };

                mta_wc_plaintexts.set(sign_peer_id, mta_wc_plaintext)?;
            }

            let mta_wc_plaintexts = mta_wc_plaintexts.unwrap_all()?;

            let proof = chaum_pedersen_k256::prove(
                &chaum_pedersen_k256::Statement {
                    base1: &k256::ProjectivePoint::generator(),
                    base2: &self.R,
                    target1: &(k256::ProjectivePoint::generator() * self.sigma_i),
                    target2: bcasts_in.get(sign_id)?.S_i.unwrap(),
                },
                &chaum_pedersen_k256::Witness {
                    scalar: &self.sigma_i,
                },
            );

            let bcast_out = serialize(&Bcast::Sad(BcastSad {
                k_i: self.k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                proof,
                mta_wc_plaintexts,
            }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r8::sad::R8 {
                    secret_key_share: self.secret_key_share,
                    msg_to_sign: self.msg_to_sign,
                    peers: self.peers,
                    keygen_id: self.keygen_id,
                    gamma_i: self.gamma_i,
                    Gamma_i: self.Gamma_i,
                    Gamma_i_reveal: self.Gamma_i_reveal,
                    w_i: self.w_i,
                    k_i: self.k_i,
                    k_i_randomness: self.k_i_randomness,
                    sigma_i: self.sigma_i,
                    l_i: self.l_i,
                    T_i: self.T_i,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    delta_inv: self.delta_inv,
                    R: self.R,
                    r5bcasts: self.r5bcasts,
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

        let bcast_out = serialize(&Bcast::Happy(BcastHappy { s_i: s_i.into() }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r8::happy::R8 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                w_i: self.w_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                T_i: self.T_i,
                r1bcasts: self.r1bcasts,
                delta_inv: self.delta_inv,
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
