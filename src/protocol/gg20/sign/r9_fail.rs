use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
    zkp::pedersen,
};
use tracing::info;

impl Sign {
    pub(super) fn r9_fail(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R8Fail));
        assert!(self.in_r8bcasts_fail.some_count() > 0);

        // DONE TO HERE

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
        let mut culprits = FillVec::with_len(self.participant_indices.len());

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r7bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // TODO don't perform verification
                    // instead, check consistency against my own culprits from r8
                    // explanation: I already performed verification in r8
                    // the only purpose of r9_fail is to detect false accusation

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

                    let culprit_index = match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            accuser
                        }
                        Err(e) => {
                            info!(
                                "participant {} detect bad proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            accused.participant_index
                        }
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
