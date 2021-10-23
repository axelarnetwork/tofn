use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, TypedUsize, VecMap},
    crypto_tools::{
        k256_serde, mta,
        paillier::{self, zk},
        zkp::pedersen,
    },
    gg20::keygen::{KeygenShareId, SecretKeyShare},
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    r1, r2, r3, r4, r5, r7,
    type5_common::{BcastSadType5, MtaPlaintext, P2pSadType5},
    KeygenShareIds, Peers, SignShareId,
};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(super) struct R6 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: Scalar,
    pub(super) peer_keygen_ids: Peers,
    pub(super) all_keygen_ids: KeygenShareIds,
    pub(super) my_keygen_id: TypedUsize<KeygenShareId>,
    pub(super) gamma_i: Scalar,
    pub(super) k_i: Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) sigma_i: Scalar,
    pub(super) l_i: Scalar,
    pub(super) beta_secrets: HoleVecMap<SignShareId, mta::Secret>,
    pub(super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(super) r4bcasts: VecMap<SignShareId, r4::BcastHappy>,
    pub(super) R: ProjectivePoint,

    #[cfg(feature = "malicious")]
    pub(super) behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    SadType5(BcastSadType5),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2p {
    Sad(P2pSad),
    SadType5(P2pSadType5),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub(super) S_i: k256_serde::ProjectivePoint,
    pub(super) S_i_proof_wc: pedersen::ProofWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pSad {
    pub(super) zkp_complaint: bool,
}

impl Executer for R6 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r5::Bcast;
    type P2p = r5::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who did not send a bcast is a faulter
        for (peer_sign_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 6",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (peer_sign_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {} in round 6",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // verify proofs
        let zkp_complaints =
            self.peer_keygen_ids
                .ref_map2_result(|(peer_sign_id, &peer_keygen_id)| {
                    let bcast = bcasts_in.get(peer_sign_id)?;
                    let zkp = &self
                        .secret_key_share
                        .group()
                        .all_shares()
                        .get(self.my_keygen_id)?
                        .zkp();
                    let peer_k_i_ciphertext = &self.r1bcasts.get(peer_sign_id)?.k_i_ciphertext;
                    let peer_ek = &self
                        .secret_key_share
                        .group()
                        .all_shares()
                        .get(peer_keygen_id)?
                        .ek();
                    let p2p_in = p2ps_in.get(peer_sign_id, my_sign_id)?;

                    let peer_stmt = &zk::range::StatementWc {
                        stmt: zk::range::Statement {
                            prover_id: peer_sign_id,
                            verifier_id: my_sign_id,
                            ciphertext: peer_k_i_ciphertext,
                            ek: peer_ek,
                        },
                        msg_g: bcast.R_i.as_ref(),
                        g: &self.R,
                    };

                    let success = zkp.verify_range_proof_wc(peer_stmt, &p2p_in.k_i_range_proof_wc);
                    if !success {
                        warn!(
                            "peer {} says: range proof wc from peer {} failed to verify",
                            my_sign_id, peer_sign_id,
                        );
                    }
                    Ok(!success)
                })?;

        corrupt!(
            zkp_complaints,
            self.corrupt_zkp_complaints(my_sign_id, zkp_complaints)?
        );

        // move to sad path if we discovered any failures
        if zkp_complaints.iter().any(|(_, complaint)| *complaint) {
            let p2ps_out = Some(zkp_complaints.map2_result(|(_, zkp_complaint)| {
                serialize(&P2p::Sad(P2pSad { zkp_complaint }))
            })?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r7::R7Sad {
                    secret_key_share: self.secret_key_share,
                    all_keygen_ids: self.all_keygen_ids,
                    r1bcasts: self.r1bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                None,
                p2ps_out,
            )));
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.R_i.as_ref()
            });

        // malicious actor falsely claim type 5 fault by comparing against a corrupted curve generator
        // TODO how best to squelch build warnings without _ prefix? https://github.com/axelarnetwork/tofn/issues/137
        let _curve_generator = ProjectivePoint::generator();
        corrupt!(_curve_generator, self.corrupt_curve_generator(info.my_id()));

        // check for type 5 fault
        if R_i_sum != _curve_generator {
            warn!("peer {} says: 'type 5' fault detected", my_sign_id);

            let mta_plaintexts =
                self.beta_secrets
                    .ref_map2_result(|(peer_sign_id, beta_secret)| {
                        let r2p2p = self.r2p2ps.get(peer_sign_id, my_sign_id)?;

                        let (alpha_plaintext, alpha_randomness) = self
                            .secret_key_share
                            .share()
                            .dk()
                            .decrypt_with_randomness(&r2p2p.alpha_ciphertext);

                        corrupt!(
                            alpha_plaintext,
                            self.corrupt_alpha_plaintext(my_sign_id, peer_sign_id, alpha_plaintext)
                        );

                        let beta_secret = beta_secret.clone();

                        corrupt!(
                            beta_secret,
                            self.corrupt_beta_secret(my_sign_id, peer_sign_id, beta_secret)
                        );

                        Ok(MtaPlaintext {
                            alpha_plaintext,
                            alpha_randomness,
                            beta_secret,
                        })
                    })?;

            let k_i = self.k_i;
            corrupt!(k_i, self.corrupt_k_i(my_sign_id, k_i));

            let bcast_out = Some(serialize(&Bcast::SadType5(BcastSadType5 {
                k_i: k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                gamma_i: self.gamma_i.into(),
            }))?);

            let p2ps_out = Some(mta_plaintexts.map2_result(|(_, mta_plaintext)| {
                serialize(&P2p::SadType5(P2pSadType5 { mta_plaintext }))
            })?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r7::R7Type5 {
                    secret_key_share: self.secret_key_share,
                    all_keygen_ids: self.all_keygen_ids,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                bcast_out,
                p2ps_out,
            )));
        }

        // happy path: compute S_i and proof
        let S_i = self.R * self.sigma_i;
        let S_i_proof_wc = pedersen::prove_wc(
            &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    prover_id: my_sign_id,
                    commit: self.r3bcasts.get(my_sign_id)?.T_i.as_ref(),
                },
                msg_g: &S_i,
                g: &self.R,
            },
            &pedersen::Witness {
                msg: &self.sigma_i,
                randomness: &self.l_i,
            },
        )?;

        corrupt!(
            S_i_proof_wc,
            self.corrupt_S_i_proof_wc(my_sign_id, S_i_proof_wc)
        );

        let bcast_out = Some(serialize(&Bcast::Happy(BcastHappy {
            S_i: S_i.into(),
            S_i_proof_wc,
        }))?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r7::R7Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peer_keygen_ids: self.peer_keygen_ids,
                all_keygen_ids: self.all_keygen_ids,
                my_keygen_id: self.my_keygen_id,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: self.r3bcasts,
                R: self.R,
                r5bcasts: bcasts_in,
                r5p2ps: p2ps_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
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
    use super::R6;
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        crypto_tools::{mta::Secret, paillier::Plaintext, zkp::pedersen},
        gg20::sign::{
            malicious::{log_confess_info, Behaviour::*},
            SignShareId,
        },
        sdk::api::TofnResult,
    };

    impl R6 {
        /// earlier we prepared to corrupt k_i by corrupting delta_i
        pub fn corrupt_k_i(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut k_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadKI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "step 2/2: k_i");
                k_i += k256::Scalar::one();
            }
            k_i
        }
        /// earlier we prepared to corrupt alpha_plaintext by corrupting delta_i
        pub fn corrupt_alpha_plaintext(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mut alpha_plaintext: Plaintext,
        ) -> Plaintext {
            if let R3BadAlpha { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.behaviour, "step 2/2: alpha_plaintext");
                    alpha_plaintext.corrupt();
                }
            }
            alpha_plaintext
        }
        /// earlier we prepared to corrupt beta_secret by corrupting delta_i
        pub fn corrupt_beta_secret(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mut beta_secret: Secret,
        ) -> Secret {
            if let R3BadBeta { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(my_sign_id, &self.behaviour, "step 2/2: beta_secret");
                    *beta_secret.beta.as_mut() += k256::Scalar::one();
                }
            }
            beta_secret
        }
        pub fn corrupt_zkp_complaints(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut zkp_complaints: HoleVecMap<SignShareId, bool>,
        ) -> TofnResult<HoleVecMap<SignShareId, bool>> {
            if let R6FalseAccusation { victim } = self.behaviour {
                let complaint = zkp_complaints.get_mut(victim)?;
                if *complaint {
                    log_confess_info(my_sign_id, &self.behaviour, "but the accusation is true");
                } else {
                    log_confess_info(my_sign_id, &self.behaviour, "");
                    *complaint = true;
                }
            }
            Ok(zkp_complaints)
        }

        #[allow(non_snake_case)]
        pub fn corrupt_S_i_proof_wc(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            range_proof: pedersen::ProofWc,
        ) -> pedersen::ProofWc {
            if let R6BadProof = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "");
                return pedersen::malicious::corrupt_proof_wc(&range_proof);
            }
            range_proof
        }

        pub fn corrupt_curve_generator(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
        ) -> k256::ProjectivePoint {
            if let R6FalseType5Claim = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "");
                return k256::ProjectivePoint::identity();
            }
            k256::ProjectivePoint::generator()
        }
    }
}
