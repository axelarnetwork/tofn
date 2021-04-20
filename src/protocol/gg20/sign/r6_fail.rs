use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
};
use tracing::info;

use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::ECPoint,
};

impl Sign {
    pub(super) fn r6_fail(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R5Fail));
        assert!(self.in_r5bcasts_fail.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r5bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // TODO don't perform verification
                    // instead, check consistency against my own culprits from r5
                    // explanation: I already performed verification in r5
                    // the only purpose of r6_fail is to detect false accusation

                    let commit = &self.in_r1bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            // TODO these checks should be unnecessary after refactoring
                            panic!(
                                "r6_fail party {} missing r1bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        })
                        .commit;
                    let r4bcast = self.in_r4bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r6_fail party {} missing r4bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        });
                    let reconstructed_commit =
                        &HashCommitment::create_commitment_with_user_defined_randomness(
                            &r4bcast.public_blind_summand.bytes_compressed_to_big_int(),
                            &r4bcast.reveal,
                        );
                    let culprit_index = if commit == reconstructed_commit {
                        info!(
                            "participant {} detect false accusation pedersen by {} against {}",
                            self.my_participant_index, accuser, accused.participant_index
                        );
                        accuser
                    } else {
                        info!(
                            "participant {} confirm bad hash commit from {}",
                            self.my_participant_index, accused.participant_index
                        );
                        accused.participant_index
                    };
                    culprits.overwrite(
                        culprit_index,
                        Criminal {
                            index: culprit_index,
                            crime_type: CrimeType::Malicious,
                        },
                    );
                }
            }
        }

        culprits
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
