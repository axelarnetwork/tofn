use tracing::error;

use crate::{
    refactor::collections::{FillVecMap, P2ps, VecMap},
    refactor::{
        keygen::{r1, r2, r3, KeygenPartyIndex, KeygenProtocolBuilder, SecretKeyShare},
        sdk::{
            api::{Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_only, log_fault_info, ProtocolBuilder, ProtocolInfo},
        },
    },
};

#[allow(non_snake_case)]
pub struct R4Sad {
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,
    pub r2bcasts: VecMap<KeygenPartyIndex, r2::Bcast>,
    pub r2p2ps: P2ps<KeygenPartyIndex, r2::P2p>,
}

impl bcast_only::Executer for R4Sad {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r3::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        // check for no complaints
        if bcasts_in
            .iter()
            .all(|(_, bcast)| matches!(bcast, r3::Bcast::Happy(_)))
        {
            error!(
                "party {} entered r4 sad path with no complaints",
                info.share_id()
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
        for (accuser, accusations) in accusations_iter {
            for (accused, accusation) in accusations.vss_complaints.into_iter_some() {
                if accuser == accused {
                    log_fault_info(info.share_id(), accuser, "self accusation");
                    faulters.set(accuser, ProtocolFault)?;
                    continue;
                }

                // verify encryption
                let accuser_ek = &self.r1bcasts.get(accuser)?.ek;
                let share_ciphertext = accuser_ek.encrypt_with_randomness(
                    &accusation.share.get_scalar().into(),
                    &accusation.randomness,
                );
                if share_ciphertext != self.r2p2ps.get(accused, accuser)?.u_i_share_ciphertext {
                    log_fault_info(info.share_id(), accused, "bad encryption");
                    faulters.set(accused, ProtocolFault)?;
                    continue;
                }

                // verify share commitment
                let accused_vss_commit = &self.r2bcasts.get(accused)?.u_i_vss_commit;
                if accused_vss_commit.validate_share(&accusation.share) {
                    log_fault_info(info.share_id(), accuser, "false accusation");
                    faulters.set(accuser, ProtocolFault)?;
                } else {
                    log_fault_info(info.share_id(), accused, "invalid vss share");
                    faulters.set(accused, ProtocolFault)?;
                }
            }
        }

        if faulters.is_empty() {
            error!("party {} r4 sad path found no faulters", info.share_id());
            return Err(TofnFatal);
        }
        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
