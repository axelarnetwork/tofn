use crate::{
    collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        constants,
        crypto_tools::{
            hash::{self},
            k256_serde,
            mta::Secret,
            paillier::{self, zk},
        },
        keygen::{KeygenShareId, SecretKeyShare},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnResult},
        implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r2, r3, r4, r6, Participants, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R5 {
    pub(crate) secret_key_share: SecretKeyShare,
    pub(crate) msg_to_sign: Scalar,
    pub(crate) peers: Peers,
    pub(crate) participants: Participants,
    pub(crate) keygen_id: TypedUsize<KeygenShareId>,
    pub(crate) gamma_i: Scalar,
    pub(crate) k_i: Scalar,
    pub(crate) k_i_randomness: paillier::Randomness,
    pub(crate) sigma_i: Scalar,
    pub(crate) l_i: Scalar,
    pub(crate) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(crate) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(crate) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub(crate) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(crate) delta_inv: Scalar,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub R_i: k256_serde::ProjectivePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub k_i_range_proof_wc: zk::range::ProofWc,
}

impl bcast_only::Executer for R5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r4::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut faulters = FillVecMap::with_size(participants_count);

        // verify commits
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_Gamma_i_commit = hash::commit_with_randomness(
                constants::GAMMA_I_COMMIT_TAG,
                bcast.Gamma_i.bytes(),
                &bcast.Gamma_i_reveal,
            );

            if peer_Gamma_i_commit != self.r1bcasts.get(sign_peer_id)?.Gamma_i_commit {
                warn!(
                    "peer {} says: Gamma_i_commit failed to verify for peer {}",
                    sign_id, sign_peer_id
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let Gamma = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.Gamma_i.unwrap()
            });

        let R = Gamma * self.delta_inv;
        let R_i = R * self.k_i;

        // statement and witness
        let k_i_ciphertext = &self.r1bcasts.get(sign_id)?.k_i_ciphertext;
        let ek = &self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.keygen_id)?
            .ek();

        let stmt_wc = &zk::range::StatementWc {
            stmt: zk::range::Statement {
                ciphertext: k_i_ciphertext,
                ek,
            },
            msg_g: &R_i,
            g: &R,
        };
        let wit = &zk::range::Witness {
            msg: &self.k_i,
            randomness: &self.k_i_randomness,
        };

        let p2ps_out = self.peers.map_ref(|(_sign_peer_id, &keygen_peer_id)| {
            let peer_zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .zkp();

            let k_i_range_proof_wc = peer_zkp.range_proof_wc(stmt_wc, wit);

            corrupt!(
                k_i_range_proof_wc,
                self.corrupt_k_i_range_proof_wc(sign_id, _sign_peer_id, k_i_range_proof_wc)
            );

            serialize(&P2p { k_i_range_proof_wc })
        })?;

        let bcast_out = serialize(&Bcast { R_i: R_i.into() })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r6::R6 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                beta_secrets: self.beta_secrets,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: self.r3bcasts,
                r4bcasts: bcasts_in,
                R,

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
    use super::R5;
    use crate::{
        collections::TypedUsize,
        gg20::{
            crypto_tools::paillier::zk::range,
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignShareId,
            },
        },
    };

    impl R5 {
        pub fn corrupt_k_i_range_proof_wc(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            range_proof: range::ProofWc,
        ) -> range::ProofWc {
            if let R5BadProof { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.behaviour, "");
                    return range::malicious::corrupt_proof_wc(&range_proof);
                }
            }
            range_proof
        }
    }
}
