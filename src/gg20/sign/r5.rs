use crate::{
    collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap, XP2ps},
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
        implementer_api::{serialize, Executer, ProtocolInfo, XProtocolBuilder, XRoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r2, r3, r4, r6, Participants, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(super) struct R5 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: Scalar,
    pub(super) peers: Peers,
    pub(super) participants: Participants,
    pub(super) keygen_id: TypedUsize<KeygenShareId>,
    pub(super) gamma_i: Scalar,
    pub(super) k_i: Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) sigma_i: Scalar,
    pub(super) l_i: Scalar,
    pub(super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(super) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub(super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(super) delta_inv: Scalar,

    #[cfg(feature = "malicious")]
    pub(super) behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(super) struct Bcast {
    pub(super) R_i: k256_serde::ProjectivePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) k_i_range_proof_wc: zk::range::ProofWc,
}

impl Executer for R5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r4::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<XProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_share_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

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
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        // verify commits
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_Gamma_i_commit = hash::commit_with_randomness(
                constants::GAMMA_I_COMMIT_TAG,
                sign_peer_id,
                bcast.Gamma_i.bytes(),
                &bcast.Gamma_i_reveal,
            );

            if peer_Gamma_i_commit != self.r1bcasts.get(sign_peer_id)?.Gamma_i_commit {
                warn!(
                    "peer {} says: Gamma_i_commit failed to verify for peer {}",
                    my_share_id, sign_peer_id
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        let Gamma = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.Gamma_i.as_ref()
            });

        let R = Gamma * self.delta_inv;
        let R_i = R * self.k_i;

        // statement and witness
        let k_i_ciphertext = &self.r1bcasts.get(my_share_id)?.k_i_ciphertext;
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

        let p2ps_out = Some(self.peers.map_ref(|(_sign_peer_id, &keygen_peer_id)| {
            let peer_zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .zkp();

            let k_i_range_proof_wc = peer_zkp.range_proof_wc(stmt_wc, wit)?;

            corrupt!(
                k_i_range_proof_wc,
                self.corrupt_k_i_range_proof_wc(my_share_id, _sign_peer_id, k_i_range_proof_wc)
            );

            serialize(&P2p { k_i_range_proof_wc })
        })?);

        let bcast_out = Some(serialize(&Bcast { R_i: R_i.into() })?);

        Ok(XProtocolBuilder::NotDone(XRoundBuilder::new(
            Box::new(r6::R6 {
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
        )))
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
