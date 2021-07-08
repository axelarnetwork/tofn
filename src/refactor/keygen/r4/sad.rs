use tracing::error;

use crate::{
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{r1, r2, r3, KeygenPartyIndex},
        protocol::{
            executer::{
                log_fault_info,
                ProtocolBuilder::{self, *},
                RoundExecuter,
            },
            Fault::ProtocolFault,
        },
    },
    vecmap::{FillVecMap, Index, P2ps, VecMap},
};

#[allow(non_snake_case)]
pub struct R4Sad {
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,
    pub r2bcasts: VecMap<KeygenPartyIndex, r2::Bcast>,
    pub r2p2ps: P2ps<KeygenPartyIndex, r2::P2p>,
}

impl RoundExecuter for R4Sad {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r3::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // check for no complaints
        if bcasts_in
            .iter()
            .all(|(_, bcast)| matches!(bcast, r3::Bcast::Happy(_)))
        {
            error!("party {} entered r4 sad path with no complaints", index);
            return Done(Err(FillVecMap::with_size(party_count)));
        }

        let mut faulters = FillVecMap::with_size(party_count);
        let accusations_iter = bcasts_in
            .into_iter()
            .filter_map(|(from, bcast)| match bcast {
                r3::Bcast::Happy(_) => None,
                r3::Bcast::Sad(accusations) => Some((from, accusations)),
            });

        // verify complaints
        for (accuser, accusations) in accusations_iter {
            for (accused, accusation) in accusations.vss_complaints.into_iter() {
                if accuser == accused {
                    log_fault_info(index, accuser, "self accusation");
                    faulters.set(accuser, ProtocolFault);
                    continue;
                }

                // verify encryption
                let accuser_ek = &self.r1bcasts.get(accuser).ek;
                let share_ciphertext = accuser_ek.encrypt_with_randomness(
                    &accusation.share.get_scalar().into(),
                    &accusation.share_randomness,
                );
                if share_ciphertext != self.r2p2ps.get(accused, accuser).u_i_share_ciphertext {
                    log_fault_info(index, accused, "bad encryption");
                    faulters.set(accused, ProtocolFault);
                    continue;
                }

                // verify share commitment
                let accused_vss_commit = &self.r2bcasts.get(accused).u_i_vss_commit;
                if accused_vss_commit.validate_share(&accusation.share) {
                    log_fault_info(index, accuser, "false accusation");
                    faulters.set(accuser, ProtocolFault);
                } else {
                    log_fault_info(index, accused, "invalid vss share");
                    faulters.set(accused, ProtocolFault);
                }
            }
        }

        if faulters.is_empty() {
            error!("party {} r4 sad found no faulters", index);
        }
        return Done(Err(faulters));
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
