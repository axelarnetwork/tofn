use super::{crimes::Crime, Sign, Status};
use crate::zkp::range;
use tracing::{info, warn};

impl Sign {
    pub(super) fn r3_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R2Fail));
        assert!(self.in_r2bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r2bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // Skip round if accuser is targeting himself; R1FalseAccusation is causing that
                    if accuser == accused.participant_index {
                        warn!("Accuser is targeting self. Skipping ...");
                        continue;
                    }

                    // TODO clarify confusion: participant vs party indices
                    let prover_ek = &self.my_secret_key_share.all_eks
                        [self.participant_indices[accused.participant_index]];
                    let prover_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r3fail party {} no r1bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        })
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let verifier_zkp =
                        &self.my_secret_key_share.all_zkps[self.participant_indices[accuser]];

                    let stmt = &range::Statement {
                        ciphertext: &prover_encrypted_ecdsa_nonce_summand,
                        ek: prover_ek,
                    };
                    let proof = &self.in_all_r1p2ps[accused.participant_index].vec_ref()[accuser]
                        .as_ref()
                        .unwrap()
                        .range_proof;
                    let verification = verifier_zkp.verify_range_proof(stmt, proof);

                    match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            criminals[accuser].push(Crime::R3FalseAccusation {
                                victim: accused.participant_index,
                            });
                        }
                        Err(e) => {
                            info!(
                                "participant {} detect bad range proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            criminals[accused.participant_index]
                                .push(Crime::R3BadRangeProof { victim: accuser });
                        }
                    };
                }
            }
        }
        criminals
    }
}
