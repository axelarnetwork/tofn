use tracing::error;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    gg20::keygen::{r1, r2, r3, KeygenProtocolBuilder, KeygenShareId, SecretKeyShare},
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, log_fault_info, ProtocolBuilder, ProtocolInfo},
    },
};

#[allow(non_snake_case)]
pub struct R4Sad {
    pub(crate) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(crate) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(crate) r2p2ps: P2ps<KeygenShareId, r2::P2p>,
}

impl bcast_only::Executer for R4Sad {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let keygen_id = info.share_id();

        // check for no complaints
        if bcasts_in
            .iter()
            .all(|(_, bcast)| matches!(bcast, r3::Bcast::Happy(_)))
        {
            error!(
                "peer {} says: entered R4 sad path with no complaints",
                keygen_id
            );
            return Err(TofnFatal);
        }

        let mut faulters = FillVecMap::with_size(info.share_count());
        let accusations_iter = bcasts_in
            .into_iter()
            .filter_map(|(from, bcast)| match bcast {
                r3::Bcast::Happy(_) => None,
                r3::Bcast::Sad(accusations) => Some((from, accusations)),
            });

        // verify complaints
        for (accuser_keygen_id, accusations) in accusations_iter {
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
