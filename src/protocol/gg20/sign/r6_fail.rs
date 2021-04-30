use super::{crimes::Crime, Sign, Status};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::ECPoint,
};
use tracing::info;

// TODO DELETE THIS FILE
// no need to perform verification because I already did it in r5
// instead, end the protocol in r5 and return criminals

impl Sign {
    pub(super) fn r6_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R5Fail));
        assert!(self.in_r5bcasts_fail.some_count() > 0);

        let mut criminals: Vec<Vec<Crime>> = (0..self.participant_indices.len())
            .map(|_| Vec::new())
            .collect(); // can't use vec![Vec::new(); capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r5bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
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
                    if commit == reconstructed_commit {
                        info!(
                            "participant {} detect false accusation pedersen by {} against {}",
                            self.my_participant_index, accuser, accused.participant_index
                        );
                        criminals[accuser].push(Crime::R6FalseAccusation {
                            victim: accused.participant_index,
                        });
                    } else {
                        info!(
                            "participant {} confirm bad hash commit from {}",
                            self.my_participant_index, accused.participant_index
                        );
                        criminals[accused.participant_index].push(Crime::R6BadHashCommit {
                            victim: accuser,
                        });
                    };
                }
            }
        }
        criminals
    }
}
