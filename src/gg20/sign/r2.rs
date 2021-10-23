use crate::{
    collections::{FillVecMap, P2ps, TypedUsize},
    crypto_tools::{
        hash, mta,
        paillier::{self, Ciphertext},
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

use super::{r1, r3, KeygenShareIds, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(super) struct R2 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: Scalar,
    pub(super) peer_keygen_ids: Peers,
    pub(super) all_keygen_ids: KeygenShareIds,
    pub(super) my_keygen_id: TypedUsize<KeygenShareId>,
    pub(super) gamma_i: Scalar,
    pub(super) Gamma_i: ProjectivePoint,
    pub(super) Gamma_i_reveal: hash::Randomness,
    pub(super) w_i: Scalar,
    pub(super) k_i: Scalar,
    pub(super) k_i_randomness: paillier::Randomness,

    #[cfg(feature = "malicious")]
    pub(super) behaviour: Behaviour,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2p {
    Happy(P2pHappy),
    Sad(P2pSad),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pHappy {
    pub(super) alpha_ciphertext: Ciphertext,
    pub(super) alpha_proof: paillier::zk::mta::Proof,
    pub(super) mu_ciphertext: Ciphertext,
    pub(super) mu_proof: paillier::zk::mta::ProofWc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pSad {
    pub(super) zkp_complaint: bool,
}

impl Executer for R2 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r1::Bcast;
    type P2p = r1::P2p;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who did not send a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 2",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {} in round 2",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // verify zk proof for first message of MtA
        let zkp_complaints =
            self.peer_keygen_ids
                .ref_map2_result(|(peer_sign_id, peer_keygen_id)| {
                    let peer_ek = &self
                        .secret_key_share
                        .group()
                        .all_shares()
                        .get(*peer_keygen_id)?
                        .ek();
                    let peer_k_i_ciphertext = &bcasts_in.get(peer_sign_id)?.k_i_ciphertext;

                    let peer_stmt = &paillier::zk::range::Statement {
                        prover_id: peer_sign_id,
                        verifier_id: my_sign_id,
                        ciphertext: peer_k_i_ciphertext,
                        ek: peer_ek,
                    };

                    let peer_proof = &p2ps_in.get(peer_sign_id, my_sign_id)?.range_proof;

                    let zkp = self
                        .secret_key_share
                        .group()
                        .all_shares()
                        .get(self.my_keygen_id)?
                        .zkp();

                    let success = zkp.verify_range_proof(peer_stmt, peer_proof);
                    if !success {
                        warn!(
                            "peer {} says: range proof from peer {} failed to verify",
                            my_sign_id, peer_sign_id,
                        );
                    }
                    Ok(!success)
                })?;

        corrupt!(
            zkp_complaints,
            self.corrupt_complaint(my_sign_id, zkp_complaints)?
        );

        // move to sad path if we discovered any failures
        if zkp_complaints.iter().any(|(_, complaint)| *complaint) {
            let p2ps_out = Some(zkp_complaints.map2_result(|(_, zkp_complaint)| {
                serialize(&P2p::Sad(P2pSad { zkp_complaint }))
            })?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r3::R3Sad {
                    secret_key_share: self.secret_key_share,
                    all_keygen_ids: self.all_keygen_ids,
                    r1bcasts: bcasts_in,
                    r1p2ps: p2ps_in,
                }),
                None,
                p2ps_out,
            )));
        }

        // TODO combine beta_secrets, nu_secrets into a single FillHoleVecMap
        let mut beta_secrets = info.new_fillholevecmap()?;
        let mut nu_secrets = info.new_fillholevecmap()?;
        let mut p2ps_out = info.new_fillholevecmap()?;

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (peer_sign_id, &peer_keygen_id) in &self.peer_keygen_ids {
            // MtA step 2 for k_i * gamma_j
            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .ek();
            let peer_k_i_ciphertext = &bcasts_in.get(peer_sign_id)?.k_i_ciphertext;
            let peer_zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .zkp();

            let (alpha_ciphertext, alpha_proof, beta_secret) = mta::mta_response_with_proof(
                my_sign_id,
                peer_sign_id,
                peer_zkp,
                peer_ek,
                peer_k_i_ciphertext,
                &self.gamma_i,
            );

            corrupt!(
                alpha_proof,
                self.corrupt_alpha_proof(my_sign_id, peer_sign_id, alpha_proof)
            );

            beta_secrets.set(peer_sign_id, beta_secret)?;

            // MtAwc step 2 for k_i * w_j
            let (mu_ciphertext, mu_proof, nu_secret) = mta::mta_response_with_proof_wc(
                my_sign_id,
                peer_sign_id,
                peer_zkp,
                peer_ek,
                peer_k_i_ciphertext,
                &self.w_i,
            )?;

            corrupt!(
                mu_proof,
                self.corrupt_mu_proof(my_sign_id, peer_sign_id, mu_proof)
            );

            nu_secrets.set(peer_sign_id, nu_secret)?;

            let p2p = serialize(&P2p::Happy(P2pHappy {
                alpha_ciphertext,
                alpha_proof,
                mu_ciphertext,
                mu_proof,
            }))?;

            p2ps_out.set(peer_sign_id, p2p)?;
        }

        let beta_secrets = beta_secrets.to_holevec()?;
        let nu_secrets = nu_secrets.to_holevec()?;
        let p2ps_out = Some(p2ps_out.to_holevec()?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r3::R3Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peer_keygen_ids: self.peer_keygen_ids,
                all_keygen_ids: self.all_keygen_ids,
                my_keygen_id: self.my_keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                w_i: self.w_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                beta_secrets,
                nu_secrets,
                r1bcasts: bcasts_in,
                r1p2ps: p2ps_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            None,
            p2ps_out,
        )))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        crypto_tools::paillier::zk::mta,
        gg20::sign::{
            malicious::{log_confess_info, Behaviour::*},
            SignShareId,
        },
        sdk::api::TofnResult,
    };

    use super::R2;

    impl R2 {
        pub fn corrupt_complaint(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut zkp_complaints: HoleVecMap<SignShareId, bool>,
        ) -> TofnResult<HoleVecMap<SignShareId, bool>> {
            if let R2FalseAccusation { victim } = self.behaviour {
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

        pub fn corrupt_alpha_proof(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            alpha_proof: mta::Proof,
        ) -> mta::Proof {
            if let R2BadMta { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(my_sign_id, &self.behaviour, "");
                    return mta::malicious::corrupt_proof(&alpha_proof);
                }
            }
            alpha_proof
        }

        pub fn corrupt_mu_proof(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            victim_sign_id: TypedUsize<SignShareId>,
            mu_proof: mta::ProofWc,
        ) -> mta::ProofWc {
            if let R2BadMtaWc { victim } = self.behaviour {
                if victim == victim_sign_id {
                    log_confess_info(my_sign_id, &self.behaviour, "");
                    return mta::malicious::corrupt_proof_wc(&mu_proof);
                }
            }
            mu_proof
        }
    }
}
