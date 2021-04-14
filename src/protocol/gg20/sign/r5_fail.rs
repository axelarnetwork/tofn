use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
    zkp::pedersen,
};
use tracing::info;

impl Sign {
    pub(super) fn r5_fail(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R4Fail));
        assert!(self.in_r4bcasts_fail.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r4bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let prover_r3bcast = self.in_r3bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "r5_fail party {} no r3bcast from {}",
                                self.my_participant_index, accused.participant_index
                            )
                        });
                    let verification = pedersen::verify(
                        &pedersen::Statement {
                            commit: &prover_r3bcast.nonce_x_keyshare_summand_commit,
                        },
                        &prover_r3bcast.nonce_x_keyshare_summand_proof,
                    );
                    let culprit_index = match verification {
                        Ok(_) => {
                            info!(
                                "participant {} detect false accusation pedersen by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            accuser
                        }
                        Err(e) => {
                            info!(
                                "participant {} confirm bad pedersen proof from {} because [{}]",
                                self.my_participant_index, accused.participant_index, e
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
