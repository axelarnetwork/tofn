use crate::{
    corrupt,
    crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, zkp::pedersen_k256},
    refactor::{
        collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
        },
        sign::{r4, Participants},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, r3, r5, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub(crate) _delta_i: Scalar, // TODO: This is only needed for tests
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2pHappy>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i: k256_serde::ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
}

impl bcast_only::Executer for R4 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r3::happy::Bcast;

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
            .any(|(_, bcast)| matches!(bcast, r3::happy::Bcast::Sad(_)))
        {
            // TODO: Should we check if this peer's P2p's are all Sad?
            warn!(
                "peer {} says: received an R3 complaint from others",
                sign_id,
            );

            return Box::new(r4::sad::R4 {
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
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in);
        }

        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| match bcast {
            r3::happy::Bcast::Happy(b) => Ok(b),
            r3::happy::Bcast::Sad(_) => Err(TofnFatal),
        })?;

        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = pedersen_k256::Statement {
                commit: bcast.T_i.unwrap(),
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            if let Err(err) = pedersen_k256::verify(&peer_stmt, &bcast.T_i_proof) {
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

        let T_i = *bcasts_in.get(sign_id)?.T_i.unwrap();

        // compute delta_inv
        let delta_inv = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| {
                acc + bcast.delta_i.unwrap()
            })
            .invert();

        if bool::from(delta_inv.is_none()) {
            warn!("peer {} says: delta inv computation failed", sign_id);
            return Err(TofnFatal);
        }

        let Gamma_i_reveal = self.Gamma_i_reveal.clone();
        corrupt!(
            Gamma_i_reveal,
            self.corrupt_Gamma_i_reveal(info.share_id(), Gamma_i_reveal)
        );

        let bcast_out = serialize(&Bcast {
            Gamma_i: self.Gamma_i.into(),
            Gamma_i_reveal: Gamma_i_reveal.clone(),
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r5::R5 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal,
                w_i: self.w_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                T_i,
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
    use super::R4;
    use crate::{
        crypto_tools::hash::Randomness,
        refactor::{
            collections::TypedUsize,
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignParticipantIndex,
            },
        },
    };

    impl R4 {
        #[allow(non_snake_case)]
        pub fn corrupt_Gamma_i_reveal(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            mut Gamma_i_reveal: Randomness,
        ) -> Randomness {
            if let R4BadReveal = self.behaviour {
                log_confess_info(me, &self.behaviour, "");
                Gamma_i_reveal.corrupt();
            }
            Gamma_i_reveal
        }
    }
}
