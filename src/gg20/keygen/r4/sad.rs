use tracing::{error, warn};

use crate::{
    collections::{FillVecMap, P2ps, VecMap, XP2ps},
    gg20::keygen::{r1, r2, r3, KeygenShareId, SecretKeyShare},
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolInfo, ProtocolBuilder},
    },
};

#[allow(non_snake_case)]
pub(in super::super) struct R4Sad {
    pub(in super::super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(in super::super) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(in super::super) r2p2ps: P2ps<KeygenShareId, r2::P2p>,
}

impl Executer for R4Sad {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let keygen_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // anyone who did not send a bcast is a faulter
        for (keygen_peer_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    keygen_id, keygen_peer_id
                );
                faulters.set(keygen_peer_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (keygen_peer_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    keygen_id, keygen_peer_id
                );
                faulters.set(keygen_peer_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent a bcast---unwrap all bcasts
        let bcasts_in = bcasts_in.to_vecmap()?;

        // we should have received at least one complaint
        if !bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            error!(
                "peer {} says: entered R4 sad path with no complaints",
                keygen_id
            );
            return Err(TofnFatal);
        }

        let accusations_iter = bcasts_in
            .into_iter()
            .filter_map(|(from, bcast)| match bcast {
                r3::Bcast::Happy(_) => None,
                r3::Bcast::Sad(accusations) => Some((from, accusations)),
            });

        // verify complaints
        for (accuser_keygen_id, accusations) in accusations_iter {
            if accusations.vss_complaints.size() != info.share_count() {
                log_fault_info(
                    keygen_id,
                    accuser_keygen_id,
                    "incorrect size of complaints vector",
                );

                faulters.set(accuser_keygen_id, ProtocolFault)?;
                continue;
            }

            if accusations.vss_complaints.is_empty() {
                log_fault_info(keygen_id, accuser_keygen_id, "no accusation found");

                faulters.set(accuser_keygen_id, ProtocolFault)?;
                continue;
            }

            for (accused_keygen_id, accusation) in accusations.vss_complaints.into_iter_some() {
                if accuser_keygen_id == accused_keygen_id {
                    log_fault_info(keygen_id, accuser_keygen_id, "self accusation");

                    faulters.set(accuser_keygen_id, ProtocolFault)?;
                    continue;
                }

                // verify encryption
                let accuser_ek = &self.r1bcasts.get(accuser_keygen_id)?.ek;
                let share_ciphertext = accuser_ek.encrypt_with_randomness(
                    &accusation.share.get_scalar().into(),
                    &accusation.randomness,
                );

                if share_ciphertext
                    != self
                        .r2p2ps
                        .get(accused_keygen_id, accuser_keygen_id)?
                        .u_i_share_ciphertext
                {
                    log_fault_info(keygen_id, accused_keygen_id, "bad encryption");

                    faulters.set(accused_keygen_id, ProtocolFault)?;
                    continue;
                }

                // verify share commitment
                let accused_vss_commit = &self.r2bcasts.get(accused_keygen_id)?.u_i_vss_commit;

                if accused_vss_commit.validate_share(&accusation.share) {
                    log_fault_info(keygen_id, accuser_keygen_id, "false accusation");

                    faulters.set(accuser_keygen_id, ProtocolFault)?;
                } else {
                    log_fault_info(keygen_id, accused_keygen_id, "invalid vss share");

                    faulters.set(accused_keygen_id, ProtocolFault)?;
                }
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R4 failure protocol found no faulters",
                keygen_id
            );
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
