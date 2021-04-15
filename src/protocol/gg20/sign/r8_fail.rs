use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
    zkp::range,
};
use tracing::info;

impl Sign {
    pub(super) fn r8_fail(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R7Fail));
        assert!(self.in_r7bcasts_fail.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r7bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // DONE TO HERE

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
