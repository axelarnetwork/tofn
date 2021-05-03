use super::{crimes::Crime, r3, Sign, Status};
use crate::{protocol::gg20::vss, zkp::mta};
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
                    if accuser == accused.participant_index {
                        let crime = Crime::R4FailFalseAccusation { victim: accuser };
                        info!(
                            "participant {} detect {:?} by {} (self accusation)",
                            self.my_participant_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                        continue;
                    }
                    let verifier_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap()
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let verifier_ek =
                        &self.my_secret_key_share.all_eks[self.participant_indices[accuser]];
                    let verifier_zkp =
                        &self.my_secret_key_share.all_zkps[self.participant_indices[accuser]];
                    let prover_r2p2p = self.in_all_r2p2ps[accused.participant_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap();

                    let verification = match &accused.crime {
                        r3::Crime::Mta => {
                            let stmt = &mta::Statement {
                                ciphertext1: &verifier_encrypted_ecdsa_nonce_summand,
                                ciphertext2: &prover_r2p2p.mta_response_blind.c,
                                ek: verifier_ek,
                            };
                            verifier_zkp.verify_mta_proof(stmt, &prover_r2p2p.mta_proof)
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
                                    ciphertext2: &prover_r2p2p.mta_response_keyshare.c,
                                    ek: verifier_ek,
                                },
                                x_g: &prover_public_key_summand,
                            };
                            verifier_zkp.verify_mta_proof_wc(stmt, &prover_r2p2p.mta_proof_wc)
                        }
                    };

                    match verification {
                        Ok(_) => {
                            let crime = Crime::R4FailFalseAccusation {
                                victim: accused.participant_index,
                            };
                            info!(
                                "participant {} detect {:?} by {}",
                                self.my_participant_index, crime, accuser
                            );
                            criminals[accuser].push(crime);
                        }
                        Err(e) => {
                            let crime = Crime::R4FailBadRangeProof { victim: accuser };
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
