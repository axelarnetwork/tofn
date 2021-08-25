use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, VecMap},
    gg20::{crypto_tools::paillier, keygen::SecretKeyShare, sign::KeygenShareIds},
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};

use tracing::{error, warn};

use super::super::{r1, r2, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R3Sad {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r1p2ps: FullP2ps<SignShareId, r1::P2p>,
}

impl Executer for R3Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = ();
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who sent a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_some() {
                warn!(
                    "peer {} says: unexpected bcast from peer {}",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {}",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // TODO refactor copied code from happy path
        // anyone who sent conflicting p2ps is a faulter
        for (from, p2ps) in p2ps_in.iter() {
            if !p2ps
                .iter()
                .all(|(_, p2p)| matches!(p2p, Self::P2p::Happy(_)))
                && !p2ps.iter().all(|(_, p2p)| matches!(p2p, Self::P2p::Sad(_)))
            {
                warn!(
                    "peer {} says: conflicting happy/sad p2ps from peer {}",
                    my_sign_id, from
                );
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let all_accusations: Vec<(_, HoleVecMap<_, r2::P2pSad>)> = p2ps_in
            .into_iter()
            .filter_map(|(from, p2ps)| {
                if p2ps
                    .iter()
                    .any(|(_to, p2p)| matches!(p2p, Self::P2p::Sad(_)))
                {
                    Some(
                        p2ps.map2_result(|(_to, p2p)| match p2p {
                            Self::P2p::Happy(_) => Err(TofnFatal),
                            Self::P2p::Sad(p2p_sad) => Ok(p2p_sad),
                        })
                        .map(|p2ps| (from, p2ps)),
                    )
                } else {
                    None
                }
            })
            .collect::<TofnResult<Vec<_>>>()?;

        // we should have received at least one complaint
        if all_accusations.is_empty() {
            error!(
                "peer {} says: R3 sad path but nobody complained",
                my_sign_id,
            );
            return Err(TofnFatal);
        }

        // verify complaints
        for (accuser_sign_id, accusations) in all_accusations {
            // anyone who sent zero complaints is a faulter
            if accusations
                .iter()
                .all(|(_, accusation)| !accusation.zkp_complaint)
            {
                warn!(
                    "peer {} says: peer {} did not accuse anyone",
                    my_sign_id, accuser_sign_id
                );
                faulters.set(accuser_sign_id, ProtocolFault)?;
            }

            for (accused_sign_id, accusation) in accusations {
                debug_assert_ne!(accused_sign_id, accuser_sign_id); // self accusation is impossible

                if !accusation.zkp_complaint {
                    continue;
                }

                let accused_keygen_id = *self.all_keygen_ids.get(accused_sign_id)?;
                let accuser_keygen_id = *self.all_keygen_ids.get(accuser_sign_id)?;

                // check r1 range proof
                let accused_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accused_keygen_id)?
                    .ek();
                let accused_k_i_ciphertext = &self.r1bcasts.get(accused_sign_id)?.k_i_ciphertext;

                let accused_stmt = &paillier::zk::range::Statement {
                    ciphertext: accused_k_i_ciphertext,
                    ek: accused_ek,
                };

                let accused_proof = &self
                    .r1p2ps
                    .get(accused_sign_id, accuser_sign_id)?
                    .range_proof;

                let accuser_zkp = self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                match accuser_zkp.verify_range_proof(accused_stmt, accused_proof) {
                    true => {
                        log_fault_info(my_sign_id, accuser_sign_id, "false accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(my_sign_id, accused_sign_id, "invalid r1 p2p range proof");
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!("peer {} says: R3 sad path found no faulters", my_sign_id);
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
