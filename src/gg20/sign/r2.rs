use crate::{
    collections::{P2ps, Subset, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{
            hash, mta,
            paillier::{self, Ciphertext},
        },
        keygen::{KeygenShareId, SecretKeyShare},
    },
    sdk::{
        api::{BytesVec, TofnResult},
        implementer_api::{bcast_and_p2p, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r3, Participants, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R2 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenShareId>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: hash::Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Bcast {
    Happy,
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub zkp_complaints: Subset<SignShareId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2p {
    Happy(P2pHappy),
    Sad,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pHappy {
    pub alpha_ciphertext: Ciphertext,
    pub alpha_proof: paillier::zk::mta::Proof,
    pub mu_ciphertext: Ciphertext,
    pub mu_proof: paillier::zk::mta::ProofWc,
}

impl bcast_and_p2p::Executer for R2 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r1::Bcast;
    type P2p = r1::P2p;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut zkp_complaints = Subset::with_max_size(participants_count);

        let mut beta_secrets = info.create_fill_hole_map(participants_count)?;
        let mut nu_secrets = info.create_fill_hole_map(participants_count)?;

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            // verify zk proof for first message of MtA
            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();
            let peer_k_i_ciphertext = &bcasts_in.get(sign_peer_id)?.k_i_ciphertext;

            let peer_stmt = &paillier::zk::range::Statement {
                ciphertext: peer_k_i_ciphertext,
                ek: peer_ek,
            };

            let peer_proof = &p2ps_in.get(sign_peer_id, sign_id)?.range_proof;

            let zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(self.keygen_id)?
                .zkp();

            if let Err(err) = zkp.verify_range_proof(peer_stmt, peer_proof) {
                warn!(
                    "peer {} says: range proof from peer {} failed to verify because [{}]",
                    sign_id, sign_peer_id, err
                );

                zkp_complaints.add(sign_peer_id)?;
            }
        }

        corrupt!(
            zkp_complaints,
            self.corrupt_complaint(info.share_id(), zkp_complaints)?
        );

        if !zkp_complaints.is_empty() {
            let bcast_out = serialize(&Bcast::Sad(BcastSad { zkp_complaints }))?;

            // TODO: Since R3 expects P2ps in the happy path but Bcast in the sad path
            // we always send bcasts and p2ps to R3, using empty P2ps and Bcasts in
            // the respective path. This adds some network overhead, so investigate a better approach.
            let p2ps_out = self.peers.map_ref(|_| serialize(&P2p::Sad))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
                round: Box::new(r3::sad::R3 {
                    secret_key_share: self.secret_key_share,
                    msg_to_sign: self.msg_to_sign,
                    peers: self.peers,
                    participants: self.participants,
                    keygen_id: self.keygen_id,
                    gamma_i: self.gamma_i,
                    Gamma_i: self.Gamma_i,
                    Gamma_i_reveal: self.Gamma_i_reveal,
                    w_i: self.w_i,
                    k_i: self.k_i,
                    k_i_randomness: self.k_i_randomness,
                    r1bcasts: bcasts_in,
                    r1p2ps: p2ps_in,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                }),
                bcast_out,
                p2ps_out,
            }));
        }

        let mut p2ps_out = info.create_fill_hole_map(participants_count)?;

        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            // MtA step 2 for k_i * gamma_j
            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();
            let peer_k_i_ciphertext = &bcasts_in.get(sign_peer_id)?.k_i_ciphertext;
            let peer_zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .zkp();

            let (alpha_ciphertext, alpha_proof, beta_secret) =
                mta::mta_response_with_proof(peer_zkp, peer_ek, peer_k_i_ciphertext, &self.gamma_i);

            corrupt!(
                alpha_proof,
                self.corrupt_alpha_proof(info.share_id(), sign_peer_id, alpha_proof)
            );

            beta_secrets.set(sign_peer_id, beta_secret)?;

            // MtAwc step 2 for k_i * w_j
            let (mu_ciphertext, mu_proof, nu_secret) =
                mta::mta_response_with_proof_wc(peer_zkp, peer_ek, peer_k_i_ciphertext, &self.w_i);

            corrupt!(
                mu_proof,
                self.corrupt_mu_proof(info.share_id(), sign_peer_id, mu_proof)
            );

            nu_secrets.set(sign_peer_id, nu_secret)?;

            let p2p = serialize(&P2p::Happy(P2pHappy {
                alpha_ciphertext,
                alpha_proof,
                mu_ciphertext,
                mu_proof,
            }))?;

            p2ps_out.set(sign_peer_id, p2p)?;
        }

        let beta_secrets = beta_secrets.unwrap_all()?;
        let nu_secrets = nu_secrets.unwrap_all()?;
        let p2ps_out = p2ps_out.unwrap_all()?;

        let bcast_out = serialize(&Bcast::Happy)?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r3::happy::R3 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
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
            bcast_out,
            p2ps_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::{Subset, TypedUsize},
        gg20::{
            crypto_tools::paillier::zk::mta,
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignShareId,
            },
        },
        sdk::api::TofnResult,
    };

    use super::R2;

    impl R2 {
        pub fn corrupt_complaint(
            &self,
            me: TypedUsize<SignShareId>,
            mut zkp_complaints: Subset<SignShareId>,
        ) -> TofnResult<Subset<SignShareId>> {
            if let R2FalseAccusation { victim } = self.behaviour {
                if zkp_complaints.is_member(victim)? {
                    log_confess_info(me, &self.behaviour, "but the accusation is true");
                } else if victim == me {
                    log_confess_info(me, &self.behaviour, "self accusation");
                    zkp_complaints.add(me)?;
                } else {
                    log_confess_info(me, &self.behaviour, "");
                    zkp_complaints.add(victim)?;
                }
            }
            Ok(zkp_complaints)
        }

        pub fn corrupt_alpha_proof(
            &self,
            me: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            alpha_proof: mta::Proof,
        ) -> mta::Proof {
            if let R2BadMta { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(me, &self.behaviour, "");
                    return mta::malicious::corrupt_proof(&alpha_proof);
                }
            }
            alpha_proof
        }

        pub fn corrupt_mu_proof(
            &self,
            me: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mu_proof: mta::ProofWc,
        ) -> mta::ProofWc {
            if let R2BadMtaWc { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(me, &self.behaviour, "");
                    return mta::malicious::corrupt_proof_wc(&mu_proof);
                }
            }
            mu_proof
        }
    }
}
