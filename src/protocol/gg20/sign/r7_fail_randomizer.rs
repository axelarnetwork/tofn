use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
    zkp::range,
};
use log::warn;
use tracing::info;

impl Sign {
    pub(super) fn r7_fail_randomizer(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R6FailRandomizer));
        assert!(self.in_r6bcasts_fail_randomizer.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        for (i, r6_participant_data) in self
            .in_r6bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r6_participant_data.is_none() {
                warn!(
                    "participant {} says: missing R6FailRandomizer data from participant {}",
                    self.my_participant_index, i
                );
                continue;
            }
            // DONE TO HERE
        }

        culprits
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
