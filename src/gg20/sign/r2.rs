use crate::{
    collections::{FillVecMap, P2ps, Subset, TypedUsize},
    corrupt,
    gg20::{
        crypto_tools::{
            hash, mta,
            paillier::{self, Ciphertext},
        },
        keygen::{KeygenShareId, SecretKeyShare},
    },
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
    pub(super) my_secret_key_share: SecretKeyShare,
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
    pub(super) my_behaviour: Behaviour,
}

// TODO: Since the happy path expects P2ps only, switch to using P2ps for issuing complaints
// so that we don't have an empty Bcast::Happy in the happy path
// https://github.com/axelarnetwork/tofn/issues/94
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Bcast {
    Happy,
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastSad {
    pub(super) zkp_complaints: Subset<SignShareId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum P2p {
    Happy(P2pHappy),
    Sad,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2pHappy {
    pub(super) alpha_ciphertext: Ciphertext,
    pub(super) alpha_proof: paillier::zk::mta::Proof,
    pub(super) mu_ciphertext: Ciphertext,
    pub(super) mu_proof: paillier::zk::mta::ProofWc,
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
        let my_share_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

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
        // anyone who did not send p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {}",
                    my_share_id, share_id
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

        let participants_count = info.total_share_count();
        let mut zkp_complaints = Subset::with_max_size(participants_count);

        let mut beta_secrets = info.new_fillholevecmap()?;
        let mut nu_secrets = info.new_fillholevecmap()?;

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (sign_peer_id, &keygen_peer_id) in &self.peer_keygen_ids {
            // verify zk proof for first message of MtA
            let peer_ek = &self
                .my_secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();
            let peer_k_i_ciphertext = &bcasts_in.get(sign_peer_id)?.k_i_ciphertext;

            let peer_stmt = &paillier::zk::range::Statement {
                ciphertext: peer_k_i_ciphertext,
                ek: peer_ek,
            };

            let peer_proof = &p2ps_in.get(sign_peer_id, my_share_id)?.range_proof;

            let zkp = &self
                .my_secret_key_share
                .group()
                .all_shares()
                .get(self.my_keygen_id)?
                .zkp();

            if !zkp.verify_range_proof(peer_stmt, peer_proof) {
                warn!(
                    "peer {} says: range proof from peer {} failed to verify",
                    my_share_id, sign_peer_id,
                );

                zkp_complaints.add(sign_peer_id)?;
            }
        }

        corrupt!(
            zkp_complaints,
            self.corrupt_complaint(my_share_id, zkp_complaints)?
        );

        if !zkp_complaints.is_empty() {
            let bcast_out = Some(serialize(&Bcast::Sad(BcastSad { zkp_complaints }))?);
            let p2ps_out = Some(
                self.peer_keygen_ids
                    .clone_map2_result(|_| serialize(&P2p::Sad))?,
            );

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r3::R3Sad {
                    secret_key_share: self.my_secret_key_share,
                    participants: self.all_keygen_ids,
                    r1bcasts: bcasts_in,
                    r1p2ps: p2ps_in,
                }),
                bcast_out,
                p2ps_out,
            )));
        }

        let mut p2ps_out = info.new_fillholevecmap()?;

        for (sign_peer_id, &keygen_peer_id) in &self.peer_keygen_ids {
            // MtA step 2 for k_i * gamma_j
            let peer_ek = &self
                .my_secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();
            let peer_k_i_ciphertext = &bcasts_in.get(sign_peer_id)?.k_i_ciphertext;
            let peer_zkp = &self
                .my_secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .zkp();

            let (alpha_ciphertext, alpha_proof, beta_secret) = mta::mta_response_with_proof(
                my_share_id,
                sign_peer_id,
                peer_zkp,
                peer_ek,
                peer_k_i_ciphertext,
                &self.gamma_i,
            );

            corrupt!(
                alpha_proof,
                self.corrupt_alpha_proof(my_share_id, sign_peer_id, alpha_proof)
            );

            beta_secrets.set(sign_peer_id, beta_secret)?;

            // MtAwc step 2 for k_i * w_j
            let (mu_ciphertext, mu_proof, nu_secret) = mta::mta_response_with_proof_wc(
                my_share_id,
                sign_peer_id,
                peer_zkp,
                peer_ek,
                peer_k_i_ciphertext,
                &self.w_i,
            )?;

            corrupt!(
                mu_proof,
                self.corrupt_mu_proof(my_share_id, sign_peer_id, mu_proof)
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

        let beta_secrets = beta_secrets.to_holevec()?;
        let nu_secrets = nu_secrets.to_holevec()?;
        let p2ps_out = Some(p2ps_out.to_holevec()?);
        let bcast_out = Some(serialize(&Bcast::Happy)?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r3::R3Happy {
                secret_key_share: self.my_secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peer_keygen_ids,
                participants: self.all_keygen_ids,
                keygen_id: self.my_keygen_id,
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
                behaviour: self.my_behaviour,
            }),
            bcast_out,
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
            sign_id: TypedUsize<SignShareId>,
            mut zkp_complaints: Subset<SignShareId>,
        ) -> TofnResult<Subset<SignShareId>> {
            if let R2FalseAccusation { victim } = self.my_behaviour {
                if zkp_complaints.is_member(victim)? {
                    log_confess_info(sign_id, &self.my_behaviour, "but the accusation is true");
                } else if victim == sign_id {
                    log_confess_info(sign_id, &self.my_behaviour, "self accusation");
                    zkp_complaints.add(sign_id)?;
                } else {
                    log_confess_info(sign_id, &self.my_behaviour, "");
                    zkp_complaints.add(victim)?;
                }
            }
            Ok(zkp_complaints)
        }

        pub fn corrupt_alpha_proof(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            alpha_proof: mta::Proof,
        ) -> mta::Proof {
            if let R2BadMta { victim } = self.my_behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.my_behaviour, "");
                    return mta::malicious::corrupt_proof(&alpha_proof);
                }
            }
            alpha_proof
        }

        pub fn corrupt_mu_proof(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mu_proof: mta::ProofWc,
        ) -> mta::ProofWc {
            if let R2BadMtaWc { victim } = self.my_behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.my_behaviour, "");
                    return mta::malicious::corrupt_proof_wc(&mu_proof);
                }
            }
            mu_proof
        }
    }
}
