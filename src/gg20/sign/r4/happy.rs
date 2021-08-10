use crate::{
    collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, zkp::pedersen},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r4, Participants},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, r3, r5, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4Happy {
    pub(crate) secret_key_share: SecretKeyShare,
    pub(crate) msg_to_sign: Scalar,
    pub(crate) peers: Peers,
    pub(crate) participants: Participants,
    pub(crate) keygen_id: TypedUsize<KeygenShareId>,
    pub(crate) gamma_i: Scalar,
    pub(crate) Gamma_i: ProjectivePoint,
    pub(crate) Gamma_i_reveal: Randomness,
    pub(crate) k_i: Scalar,
    pub(crate) k_i_randomness: paillier::Randomness,
    pub(crate) sigma_i: Scalar,
    pub(crate) l_i: Scalar,
    pub(crate) _delta_i: Scalar,
    pub(crate) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(crate) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(crate) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i: k256_serde::ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
}

impl bcast_only::Executer for R4Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r3::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut faulters = FillVecMap::with_size(participants_count);

        // check for complaints
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            warn!(
                "peer {} says: received an R3 complaint from others",
                sign_id,
            );

            return Box::new(r4::R4Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in);
        }

        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| match bcast {
            r3::Bcast::Happy(b) => Ok(b),
            r3::Bcast::Sad(_) => Err(TofnFatal),
        })?;

        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = pedersen::Statement {
                commit: bcast.T_i.as_ref(),
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            if let Err(err) = pedersen::verify(&peer_stmt, &bcast.T_i_proof) {
                warn!(
                    "peer {} says: pedersen proof failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // compute delta_inv
        let delta_inv = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| {
                acc + bcast.delta_i.as_ref()
            })
            .invert();

        // TODO: A malicious attacker can make it so that the delta_i sum is equal to 0,
        // so that delta_inv is not defined. While the protocol accounts for maliciously
        // chosen delta_i values, it only does this verification later, and we need to
        // compute delta_inv to reach that stage. So, this seems to be an oversight in the
        // protocol spec. While the fix to identify the faulter is easy, this will be changed
        // after discussion with the authors.
        if bool::from(delta_inv.is_none()) {
            warn!("peer {} says: delta inv computation failed", sign_id);
            return Err(TofnFatal);
        }

        let Gamma_i_reveal = self.Gamma_i_reveal.clone();
        corrupt!(
            Gamma_i_reveal,
            self.corrupt_Gamma_i_reveal(sign_id, Gamma_i_reveal)
        );

        let bcast_out = serialize(&Bcast {
            Gamma_i: self.Gamma_i.into(),
            Gamma_i_reveal,
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r5::R5 {
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
                r3bcasts: bcasts_in,
                delta_inv: delta_inv.unwrap(),

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
    use super::R4Happy;
    use crate::{
        collections::TypedUsize,
        gg20::{
            crypto_tools::hash::Randomness,
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignShareId,
            },
        },
    };

    impl R4Happy {
        #[allow(non_snake_case)]
        pub fn corrupt_Gamma_i_reveal(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut Gamma_i_reveal: Randomness,
        ) -> Randomness {
            if let R4BadReveal = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                Gamma_i_reveal.corrupt();
            }
            Gamma_i_reveal
        }
    }
}
