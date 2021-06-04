use super::{crimes::Crime, Sign, Status};
use crate::paillier_k256::zk;
use tracing::info;

impl Sign {
    pub(super) fn r3_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R2Fail));
        assert!(self.in_r2bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r2bcasts_fail.vec_ref()[accuser].as_ref() {
                // TODO don't allow duplicate complaints
                for accused in fail_bcast.culprits.iter() {
                    if accuser == accused.participant_index {
                        let crime = Crime::R3FailFalseAccusation { victim: accuser };
                        info!(
                            "participant {} detect {:?} by {} (self accusation)",
                            self.my_participant_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                        continue;
                    }

                    // check proof
                    let prover_ek_k256 = &self.my_secret_key_share.all_eks_k256
                        [self.participant_indices[accused.participant_index]];
                    let prover_k_i_ciphertext = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .k_i_ciphertext_k256;
                    let verifier_zkp_k256 =
                        &self.my_secret_key_share.all_zkps_k256[self.participant_indices[accuser]];
                    let stmt_k256 = &zk::range::Statement {
                        ciphertext: &prover_k_i_ciphertext,
                        ek: prover_ek_k256,
                    };
                    let proof_k256 = &self.in_all_r1p2ps[accused.participant_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap()
                        .range_proof_k256;

                    match verifier_zkp_k256.verify_range_proof(stmt_k256, proof_k256) {
                        Ok(_) => {
                            let crime = Crime::R3FailFalseAccusation {
                                victim: accused.participant_index,
                            };
                            info!(
                                "participant {} detect {:?} by {}",
                                self.my_participant_index, crime, accuser
                            );
                            criminals[accuser].push(crime);
                        }
                        Err(e) => {
                            let crime = Crime::R3FailBadRangeProof { victim: accuser };
                            info!(
                                "participant {} detect {:?} by {} because [{}]",
                                self.my_participant_index, crime, accuser, e
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
