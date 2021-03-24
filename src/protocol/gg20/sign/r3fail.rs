use super::{Sign, Status};
use crate::zkp::range;

impl Sign {
    pub(super) fn r3fail(&self) -> Vec<usize> {
        assert!(matches!(self.status, Status::R2Fail));
        assert!(self.in_r2bcasts_fail.some_count() > 0);

        let mut culprits = vec![false; self.participant_indices.len()];

        for &accuser in self.participant_indices.iter() {
            if let Some(fail_bcast) = self.in_r2bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let prover_ek = &self.my_secret_key_share.all_eks[accused.participant_index];
                    let prover_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let verifier_zkp = &self.my_secret_key_share.all_zkps[accuser];

                    let verification = verifier_zkp.verify_range_proof(
                        &range::Statement {
                            ciphertext: &prover_encrypted_ecdsa_nonce_summand,
                            ek: prover_ek,
                        },
                        &self.in_all_r1p2ps[accused.participant_index].vec_ref()[accuser]
                            .as_ref()
                            .unwrap()
                            .range_proof,
                    );
                    let culprit_index = match verification {
                        Ok(_) => accuser,
                        Err(_) => accused.participant_index,
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
