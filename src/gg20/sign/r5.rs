use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, TypedUsize, VecMap},
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
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r2, r3, r4, r6, KeygenShareIds, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(super) struct R5 {
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
    pub(super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
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
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who did not send a bcast is a faulter
        for (peer_sign_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (peer_sign_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
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

        // verify commits
        for (peer_sign_id, bcast) in &bcasts_in {
            let peer_Gamma_i_commit = hash::commit_with_randomness(
                constants::GAMMA_I_COMMIT_TAG,
                peer_sign_id,
                bcast.Gamma_i.bytes(),
                &bcast.Gamma_i_reveal,
            );

            if peer_Gamma_i_commit != self.r1bcasts.get(peer_sign_id)?.Gamma_i_commit {
                warn!(
                    "peer {} says: Gamma_i_commit failed to verify for peer {}",
                    my_sign_id, peer_sign_id
                );

                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let Gamma = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.Gamma_i.as_ref()
            });

        let R = Gamma * self.delta_inv;
        let R_i = R * self.k_i;

        // statement and witness
        let k_i_ciphertext = &self.r1bcasts.get(my_sign_id)?.k_i_ciphertext;
        let ek = &self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.my_keygen_id)?
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

        let p2ps_out = Some(self.peer_keygen_ids.clone_map2_result(
            |(_peer_sign_id, &peer_keygen_id)| {
                let peer_zkp = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(peer_keygen_id)?
                    .zkp();

                let k_i_range_proof_wc = peer_zkp.range_proof_wc(stmt_wc, wit)?;

                corrupt!(
                    k_i_range_proof_wc,
                    self.corrupt_k_i_range_proof_wc(my_sign_id, _peer_sign_id, k_i_range_proof_wc)
                );

                serialize(&P2p { k_i_range_proof_wc })
            },
        )?);

        let bcast_out = Some(serialize(&Bcast { R_i: R_i.into() })?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r6::R6 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peer_keygen_ids: self.peer_keygen_ids,
                all_keygen_ids: self.all_keygen_ids,
                my_keygen_id: self.my_keygen_id,
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
