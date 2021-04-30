use super::{crimes::Crime, Sign, Status};
use crate::zkp::pedersen;
use tracing::info;

// TODO DELETE THIS FILE
// no need to perform verification because I already did it in r7
// instead, end the protocol in r7 and return criminals

impl Sign {
    pub(super) fn r8_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R7Fail));
        assert!(self.in_r7bcasts_fail.some_count() > 0);

        let ecdsa_randomizer = &self
            .r5state
            .as_ref()
            .unwrap_or_else(|| {
                // TODO these checks should be unnecessary after refactoring
                panic!(
                    "r8fail party {} hey where did my r5state go!?",
                    self.my_participant_index
                )
            })
            .ecdsa_randomizer;
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r7bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let prover_commit = &self.in_r3bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                            // TODO these checks should be unnecessary after refactoring
                            "r8_fail party {} missing r3bcast from {}",
                            self.my_participant_index, accused.participant_index
                        )
                        })
                        .nonce_x_keyshare_summand_commit;
                    let prover_r6bcast = self.in_r6bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                            // TODO these checks should be unnecessary after refactoring
                            "r8_fail party {} missing r6bcast from {}",
                            self.my_participant_index, accused.participant_index
                        )
                        });

                    let verification = pedersen::verify_wc(
                        &pedersen::StatementWc {
                            stmt: pedersen::Statement {
                                commit: prover_commit,
                            },
                            msg_g: &prover_r6bcast.ecdsa_public_key_check,
                            g: ecdsa_randomizer,
                        },
                        &prover_r6bcast.ecdsa_public_key_check_proof_wc,
                    );

                    match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            criminals[accuser].push(Crime::R8FalseAccusation {
                                victim: accused.participant_index,
                            });
                        }
                        Err(e) => {
                            info!(
                                "participant {} detect bad range proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            let crime = Crime::R8BadRangeProof;
                            if !criminals[accused.participant_index].contains(&crime) {
                                criminals[accused.participant_index].push(crime);
                            }
                        }
                    };
                }
            }
        }
        criminals
    }
}
