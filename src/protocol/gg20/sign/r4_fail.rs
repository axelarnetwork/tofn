use super::{r3, Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{gg20::vss, CrimeType, Criminal},
    zkp::mta,
};
use tracing::{info, warn};

impl Sign {
    pub(super) fn r4_fail(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R3Fail));
        assert!(self.in_r3bcasts_fail.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r3bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    // Skip round if accuser is targeting himself; R2FalseAccusationMta is causing that
                    if accuser == accused.participant_index {
                        warn!("Accuser is targeting self. Skipping ...");
                        continue;
                    }
                    let verifier_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r4fail party {} no r1bcast from {}",
                                self.my_participant_index, accuser
                            )
                        })
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let verifier_ek =
                        &self.my_secret_key_share.all_eks[self.participant_indices[accuser]];
                    let verifier_zkp =
                        &self.my_secret_key_share.all_zkps[self.participant_indices[accuser]];
                    let prover_r2p2p = self.in_all_r2p2ps[accused.participant_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r4fail party {} no r2p2p from {} to {}",
                                self.my_participant_index, accused.participant_index, accuser
                            )
                        });

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

                    let culprit_index = match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation mta by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            accuser
                        }
                        Err(e) => {
                            info!(
                                "participant {} detect bad mta proof from {} to {} because [{}]",
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
