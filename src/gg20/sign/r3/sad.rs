use crate::{
    collections::{FillVecMap, FullP2ps, VecMap},
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
    pub(in super::super) participants: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r1p2ps: FullP2ps<SignShareId, r1::P2p>,
}

impl Executer for R3Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: crate::collections::P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<crate::sdk::implementer_api::ProtocolBuilder<Self::FinalOutput, Self::Index>>
    {
        let my_share_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // TODO sad path should not have p2ps

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
        let _p2ps_in = p2ps_in.to_fullp2ps()?;

        let participants_count = info.share_count();

        // we should have received at least one complaint
        if !bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r2::Bcast::Sad(_)))
        {
            error!(
                "peer {} says: R3 sad path but nobody complained",
                my_share_id,
            );

            return Err(TofnFatal);
        }

        let accusations_iter =
            bcasts_in
                .into_iter()
                .filter_map(|(sign_peer_id, bcast)| match bcast {
                    r2::Bcast::Happy => None,
                    r2::Bcast::Sad(accusations) => Some((sign_peer_id, accusations)),
                });

        // verify complaints
        for (accuser_sign_id, accusations) in accusations_iter {
            if accusations.zkp_complaints.max_size() != participants_count {
                log_fault_info(
                    my_share_id,
                    accuser_sign_id,
                    "incorrect size of complaints vector",
                );

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            if accusations.zkp_complaints.is_empty() {
                log_fault_info(my_share_id, accuser_sign_id, "no accusation found");

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            for accused_sign_id in accusations.zkp_complaints.iter() {
                if accuser_sign_id == accused_sign_id {
                    log_fault_info(my_share_id, accuser_sign_id, "self accusation");
                    faulters.set(accuser_sign_id, ProtocolFault)?;
                    continue;
                }

                let accused_keygen_id = *self.participants.get(accused_sign_id)?;
                let accuser_keygen_id = *self.participants.get(accuser_sign_id)?;

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

                let accuser_zkp = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                match accuser_zkp.verify_range_proof(accused_stmt, accused_proof) {
                    true => {
                        log_fault_info(my_share_id, accuser_sign_id, "false accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(my_share_id, accused_sign_id, "invalid r1 p2p range proof");
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!("peer {} says: R3 sad path found no faulters", my_share_id);
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
