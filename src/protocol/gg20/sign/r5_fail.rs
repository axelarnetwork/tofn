use super::{crimes::Crime, Sign, Status};
use crate::zkp::pedersen;
use tracing::info;

impl Sign {
    pub(super) fn r5_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R4Fail));
        assert!(self.in_r4bcasts_fail.some_count() > 0);

        let mut criminals: Vec<Vec<Crime>> = (0..self.participant_indices.len())
            .map(|_| Vec::new())
            .collect(); // can't use vec![Vec::new(); capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r4bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let prover_r3bcast = self.in_r3bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r5_fail party {} no r3bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        });
                    let verification = pedersen::verify(
                        &pedersen::Statement {
                            commit: &prover_r3bcast.nonce_x_keyshare_summand_commit,
                        },
                        &prover_r3bcast.nonce_x_keyshare_summand_proof,
                    );
                    match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation pedersen by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            criminals[accuser].push(Crime::R5FalseAccusation {
                                victim: accused.participant_index,
                            });
                        }
                        Err(e) => {
                            info!(
                                "participant {} confirm bad pedersen range proof from {} because [{}]",
                                self.my_participant_index, accused.participant_index, e
                            );
                            let crime = Crime::R5BadRangeProof;
                            if !criminals[accused.participant_index].contains(&crime) {
                                criminals[accused.participant_index].push(Crime::R5BadRangeProof);
                            }
                        }
                    };
                }
            }
        }
        criminals
    }
}
