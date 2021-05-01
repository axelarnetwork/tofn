use super::{crimes::Crime, Sign, Status};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::ECPoint,
};
use tracing::info;

// TODO DELETE THIS FILE
// no need to perform verification because I already did it in r5
// instead, end the protocol in r5 and return criminals

impl Sign {
    pub(super) fn r6_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R5Fail));
        assert!(self.in_r5bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r5bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let commit = &self.in_r1bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .commit;
                    let r4bcast = self.in_r4bcasts.vec_ref()[accused.participant_index]
                        .as_ref()
                        .unwrap();
                    let reconstructed_commit =
                        &HashCommitment::create_commitment_with_user_defined_randomness(
                            &r4bcast.public_blind_summand.bytes_compressed_to_big_int(),
                            &r4bcast.reveal,
                        );
                    if commit == reconstructed_commit {
                        let crime = Crime::R6FalseAccusation {
                            victim: accused.participant_index,
                        };
                        info!(
                            "participant {} detect {:?} by {}",
                            self.my_participant_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                    } else {
                        let crime = Crime::R6BadHashCommit;
                        info!(
                            "participant {} detect {:?} by {}",
                            self.my_participant_index, crime, accused.participant_index
                        );
                        if !criminals[accused.participant_index].contains(&crime) {
                            criminals[accused.participant_index].push(crime);
                        }
                    };
                }
            }
        }
        criminals
    }
}
