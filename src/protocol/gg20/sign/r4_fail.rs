use super::{crimes::Crime, r3, Sign, Status};
use crate::paillier_k256::zk;
use crate::protocol::gg20::vss_k256;
use crate::{protocol::gg20::vss, zkp::paillier::mta};
use tracing::info;

impl Sign {
    pub(super) fn r4_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R3Fail));
        assert!(self.in_r3bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r3bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // check for self-accusation
                    if accuser == accused.participant_index {
                        let crime = match &accused.crime {
                            r3::Crime::Mta => Crime::R4FailFalseAccusationMta { victim: accuser },
                            r3::Crime::MtaWc => {
                                Crime::R4FailFalseAccusationMtaWc { victim: accuser }
                            }
                        };
                        info!(
                            "participant {} detect {:?} by {} (self accusation)",
                            self.my_participant_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                        continue;
                    }

                    // curv: check proofs
                    let verifier_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap()
                        .k_i_ciphertext
                        .c;
                    let verifier_ek =
                        &self.my_secret_key_share.all_eks[self.participant_indices[accuser]];
                    let verifier_zkp =
                        &self.my_secret_key_share.all_zkps[self.participant_indices[accuser]];
                    let prover_r2p2p = self.in_all_r2p2ps[accused.participant_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap();
                    match &accused.crime {
                        r3::Crime::Mta => {
                            let stmt = &mta::Statement {
                                ciphertext1: &verifier_encrypted_ecdsa_nonce_summand,
                                ciphertext2: &prover_r2p2p.alpha_ciphertext.c,
                                ek: verifier_ek,
                            };
                            match verifier_zkp.verify_mta_proof(stmt, &prover_r2p2p.alpha_proof) {
                                Ok(_) => {
                                    let crime = Crime::R4FailFalseAccusationMta {
                                        victim: accused.participant_index,
                                    };
                                    info!(
                                        "participant {} detect {:?} by {}",
                                        self.my_participant_index, crime, accuser
                                    );
                                    // do not accuse curv crimes
                                    // criminals[accuser].push(crime);
                                }
                                Err(e) => {
                                    let crime = Crime::R4FailBadMta { victim: accuser };
                                    info!(
                                        "participant {} detect {:?} by {} because [{}]",
                                        self.my_participant_index,
                                        crime,
                                        accused.participant_index,
                                        e
                                    );
                                    // do not accuse curv crimes
                                    // criminals[accused.participant_index].push(crime);
                                }
                            };
                        }
                        r3::Crime::MtaWc => {
                            let prover_party_index =
                                self.participant_indices[accused.participant_index];
                            let prover_public_key_summand = self
                                .my_secret_key_share
                                .all_ecdsa_public_key_shares[prover_party_index]
                                * vss::lagrangian_coefficient(
                                    self.my_secret_key_share.share_count,
                                    prover_party_index,
                                    &self.participant_indices,
                                );

                            let stmt = &mta::StatementWc {
                                stmt: mta::Statement {
                                    ciphertext1: &verifier_encrypted_ecdsa_nonce_summand,
                                    ciphertext2: &prover_r2p2p.mu_ciphertext.c,
                                    ek: verifier_ek,
                                },
                                x_g: &prover_public_key_summand,
                            };

                            match verifier_zkp.verify_mta_proof_wc(stmt, &prover_r2p2p.mu_proof) {
                                Ok(_) => {
                                    let crime = Crime::R4FailFalseAccusationMtaWc {
                                        victim: accused.participant_index,
                                    };
                                    info!(
                                        "participant {} detect {:?} by {}",
                                        self.my_participant_index, crime, accuser
                                    );
                                    // do not accuse curv crimes
                                    // criminals[accuser].push(crime);
                                }
                                Err(e) => {
                                    let crime = Crime::R4FailBadMtaWc { victim: accuser };
                                    info!(
                                        "participant {} detect {:?} by {} because [{}]",
                                        self.my_participant_index,
                                        crime,
                                        accused.participant_index,
                                        e
                                    );
                                    // do not accuse curv crimes
                                    // criminals[accused.participant_index].push(crime);
                                }
                            };
                        }
                    };

                    // k256: check proofs
                    let verifier_k_i_ciphertext_k256 = &self.in_r1bcasts.vec_ref()[accuser]
                        .as_ref()
                        .unwrap()
                        .k_i_ciphertext_k256;
                    let verifier_ek_k256 =
                        &self.my_secret_key_share.all_eks_k256[self.participant_indices[accuser]];
                    let verifier_zkp_k256 =
                        &self.my_secret_key_share.all_zkps_k256[self.participant_indices[accuser]];
                    let prover_r2p2p = self.in_all_r2p2ps[accused.participant_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap();
                    match &accused.crime {
                        r3::Crime::Mta => {
                            let stmt_k256 = &zk::mta::Statement {
                                ciphertext1: &verifier_k_i_ciphertext_k256,
                                ciphertext2: &prover_r2p2p.alpha_ciphertext_k256,
                                ek: verifier_ek_k256,
                            };
                            match verifier_zkp_k256
                                .verify_mta_proof(stmt_k256, &prover_r2p2p.alpha_proof_k256)
                            {
                                Ok(_) => {
                                    let crime = Crime::R4FailFalseAccusationMta {
                                        victim: accused.participant_index,
                                    };
                                    info!(
                                        "participant {} detect {:?} by {}",
                                        self.my_participant_index, crime, accuser
                                    );
                                    criminals[accuser].push(crime);
                                }
                                Err(e) => {
                                    let crime = Crime::R4FailBadMta { victim: accuser };
                                    info!(
                                        "participant {} detect {:?} by {} because [{}]",
                                        self.my_participant_index,
                                        crime,
                                        accused.participant_index,
                                        e
                                    );
                                    criminals[accused.participant_index].push(crime);
                                }
                            };
                        }
                        r3::Crime::MtaWc => {
                            let prover_party_index =
                                self.participant_indices[accused.participant_index];
                            let prover_y_i_k256 =
                                self.my_secret_key_share.all_y_i_k256[prover_party_index].unwrap()
                                    * &vss_k256::lagrange_coefficient(
                                        accused.participant_index,
                                        &self.participant_indices,
                                    );

                            let stmt_k256 = &zk::mta::StatementWc {
                                stmt: zk::mta::Statement {
                                    ciphertext1: &verifier_k_i_ciphertext_k256,
                                    ciphertext2: &prover_r2p2p.mu_ciphertext_k256,
                                    ek: verifier_ek_k256,
                                },
                                x_g: &prover_y_i_k256,
                            };

                            match verifier_zkp_k256
                                .verify_mta_proof_wc(stmt_k256, &prover_r2p2p.mu_proof_k256)
                            {
                                Ok(_) => {
                                    let crime = Crime::R4FailFalseAccusationMtaWc {
                                        victim: accused.participant_index,
                                    };
                                    info!(
                                        "participant {} detect {:?} by {}",
                                        self.my_participant_index, crime, accuser
                                    );
                                    criminals[accuser].push(crime);
                                }
                                Err(e) => {
                                    let crime = Crime::R4FailBadMtaWc { victim: accuser };
                                    info!(
                                        "participant {} detect {:?} by {} because [{}]",
                                        self.my_participant_index,
                                        crime,
                                        accused.participant_index,
                                        e
                                    );
                                    criminals[accused.participant_index].push(crime);
                                }
                            };
                        }
                    };
                }
            }
        }
        criminals
    }
}
