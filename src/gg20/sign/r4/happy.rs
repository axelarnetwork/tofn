use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, zkp::pedersen},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r4, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, r3, r5, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(in super::super) struct R4Happy {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) msg_to_sign: Scalar,
    pub(in super::super) peers: Peers,
    pub(in super::super) participants: KeygenShareIds,
    pub(in super::super) keygen_id: TypedUsize<KeygenShareId>,
    pub(in super::super) gamma_i: Scalar,
    pub(in super::super) Gamma_i: ProjectivePoint,
    pub(in super::super) Gamma_i_reveal: Randomness,
    pub(in super::super) k_i: Scalar,
    pub(in super::super) k_i_randomness: paillier::Randomness,
    pub(in super::super) sigma_i: Scalar,
    pub(in super::super) l_i: Scalar,
    pub(in super::super) _delta_i: Scalar,
    pub(in super::super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,

    #[cfg(feature = "malicious")]
    pub(in super::super) behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(in super::super) struct Bcast {
    pub(in super::super) Gamma_i: k256_serde::ProjectivePoint,
    pub(in super::super) Gamma_i_reveal: Randomness,
}

impl Executer for R4Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r3::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: crate::collections::P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<crate::sdk::implementer_api::ProtocolBuilder<Self::FinalOutput, Self::Index>>
    {
        let my_share_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

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
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if bcasts_in
            .iter()
            .any(|(_, bcast_option)| matches!(bcast_option, Some(r3::Bcast::Sad(_))))
        {
            warn!(
                "peer {} says: received an R3 complaint from others",
                my_share_id,
            );

            return Box::new(r4::R4Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| match bcast {
            r3::Bcast::Happy(b) => Ok(b),
            r3::Bcast::Sad(_) => Err(TofnFatal),
        })?;

        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = pedersen::Statement {
                prover_id: sign_peer_id,
                commit: bcast.T_i.as_ref(),
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            if !pedersen::verify(&peer_stmt, &bcast.T_i_proof) {
                warn!(
                    "peer {} says: pedersen proof failed to verify for peer {}",
                    my_share_id, sign_peer_id,
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
            warn!("peer {} says: delta inv computation failed", my_share_id);
            return Err(TofnFatal);
        }

        let Gamma_i_reveal = self.Gamma_i_reveal.clone();
        corrupt!(
            Gamma_i_reveal,
            self.corrupt_Gamma_i_reveal(my_share_id, Gamma_i_reveal)
        );

        let bcast_out = Some(serialize(&Bcast {
            Gamma_i: self.Gamma_i.into(),
            Gamma_i_reveal,
        })?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r5::R5 {
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
