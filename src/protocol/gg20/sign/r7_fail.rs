use super::{crimes::Crime, Sign, Status};
use crate::zkp::range;
use tracing::{info, warn};

impl Sign {
    pub(super) fn r7_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R6Fail));
        assert!(self.in_r6bcasts_fail.some_count() > 0);

        let mut criminals: Vec<Vec<Crime>> = (0..self.participant_indices.len())
            .map(|_| Vec::new())
            .collect(); // can't use vec![Vec::new(); capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r6bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // Skip round if accuser is targeting himself; R5FalseAccusation is causing that
                    if accuser == accused.participant_index {
                        warn!("Accuser is targeting self. Skipping ...");
                        continue;
                    }
                    let prover_ek = &self.my_secret_key_share.all_eks
                        [self.participant_indices[accused.participant_index]];
                    let prover_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                // TODO these checks should be unnecessary after refactoring
                                "r7fail party {} missing r1bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        })
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let prover_ecdsa_randomizer_x_nonce_summand = &self.in_r5bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                // TODO these checks should be unnecessary after refactoring
                                "r7fail party {} missing r5bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        })
                        .ecdsa_randomizer_x_nonce_summand;
                    let ecdsa_randomizer = &self
                        .r5state
                        .as_ref()
                        .unwrap_or_else(|| {
                            // TODO these checks should be unnecessary after refactoring
                            panic!(
                                "r7fail party {} hey where did my r5state go!?",
                                self.my_participant_index
                            )
                        })
                        .ecdsa_randomizer;
                    let verifier_zkp =
                        &self.my_secret_key_share.all_zkps[self.participant_indices[accuser]];

                    let stmt = &range::StatementWc {
                        stmt: range::Statement {
                            ciphertext: prover_encrypted_ecdsa_nonce_summand,
                            ek: prover_ek,
                        },
                        msg_g: prover_ecdsa_randomizer_x_nonce_summand,
                        g: ecdsa_randomizer,
                    };
                    let proof = &self.in_all_r5p2ps[accused.participant_index].vec_ref()[accuser]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                // TODO these checks should be unnecessary after refactoring
                                "r7fail party {} missing r5p2p from {} to {}",
                                self.my_participant_index, accused.participant_index, accuser
                            )
                        })
                        .ecdsa_randomizer_x_nonce_summand_proof;

                    let verification = verifier_zkp.verify_range_proof_wc(stmt, proof);
                    match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            criminals[accuser].push(Crime::R7FalseAccusation {
                                victim: accused.participant_index,
                            });
                        }
                        Err(e) => {
                            info!(
                                "participant {} detect bad range proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            criminals[accused.participant_index]
                                .push(Crime::R7BadRangeProof { victim: accuser });
                        }
                    };
                }
            }
        }
        criminals
    }
}
