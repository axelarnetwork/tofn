use super::{Sign, Status};
use crate::zkp::range;

impl Sign {
    pub(super) fn r3fail(&self) -> Vec<usize> {
        assert!(matches!(self.status, Status::R2Fail));
        assert!(self.in_r2bcasts_fail.some_count() > 0);

        let mut culprits = vec![false; self.participant_indices.len()];

        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r2bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
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

                    let culprit_index = match verification {
                        Ok(_) => {
                            println!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            accuser
                        }
                        Err(e) => {
                            println!(
                                "participant {} detect bad proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            accused.participant_index
                        }
                    };
                    culprits[culprit_index] = true;
                }
            }
        }

        culprits
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b { Some(i) } else { None })
            .collect()
    }
}