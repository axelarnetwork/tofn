use super::{crimes::Crime, Sign, Status};
use crate::zkp::range;
use tracing::info;

impl Sign {
    pub(super) fn r7_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R6Fail));
        assert!(self.in_r6bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r6bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    if accuser == accused.participant_index {
                        let crime = Crime::R7FalseAccusation { victim: accuser };
                        info!(
                            "participant {} detect {:?} by {} (self accusation)",
                            self.my_participant_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                        continue;
                    }
                    let prover_ek = &self.my_secret_key_share.all_eks
                        [self.participant_indices[accused.participant_index]];
                    let prover_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let prover_ecdsa_randomizer_x_nonce_summand = &self.in_r5bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .ecdsa_randomizer_x_nonce_summand;
                    let ecdsa_randomizer = &self.r5state.as_ref().unwrap().ecdsa_randomizer;
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
                        .unwrap()
                        .ecdsa_randomizer_x_nonce_summand_proof;

                    let verification = verifier_zkp.verify_range_proof_wc(stmt, proof);
                    match verification {
                        Ok(_) => {
                            let crime = Crime::R7FalseAccusation {
                                victim: accused.participant_index,
                            };
                            info!(
                                "participant {} detect {:?} by {}",
                                self.my_participant_index, crime, accuser
                            );
                            criminals[accuser].push(crime);
                        }
                        Err(e) => {
                            let crime = Crime::R7BadRangeProof { victim: accuser };
                            info!(
                                "participant {} detect {:?} by {} because [{}]",
                                self.my_participant_index, crime, accused.participant_index, e
                            );
                            criminals[accused.participant_index].push(crime);
                        }
                    };
                }
            }
        }
        criminals
    }
}
