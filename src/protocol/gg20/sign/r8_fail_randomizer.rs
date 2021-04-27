use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
};
// use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
// use log::warn;
// use serde::{Deserialize, Serialize};
use tracing::warn;

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r8_fail_randomizer(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R7FailRandomizer));
        assert!(self.in_r7bcasts_fail_randomizer.some_count() > 0);

        let mut criminals = FillVec::with_len(self.participant_indices.len());

        // TODO TEMPORARY TEST CODE
        for (i, r7_participant_data) in self
            .in_r7bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r7_participant_data.is_none() {
                // we took an extra round to ensure all other parties know to switch to blame mode
                // thus, any party that did not send abort data must be a criminal
                warn!(
                    "participant {} says: participant {} failed to send R7FailRandomizer data",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
            }
        }

        criminals
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
