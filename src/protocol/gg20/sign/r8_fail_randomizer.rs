use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    GE,
};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};
use tracing::warn;

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r8_fail_randomizer(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R7FailRandomizer));
        assert!(self.in_r7bcasts_fail_randomizer.some_count() > 0);

        let mut criminals = FillVec::with_len(self.participant_indices.len());

        for (i, r7_participant_data) in self
            .in_r7bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r7_participant_data.is_none() {
                // we took an extra round to ensure all other parties know to switch to blame mode
                // thus, any party that did not send abort data must be a criminal
                // TODO is that party a criminal even in case of timeout?
                warn!(
                    "participant {} says: participant {} failed to send R7FailRandomizer data",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
                continue; // participant i is known to be criminal, continue to next participant
            }
            let r7_participant_data = r7_participant_data.as_ref().unwrap();

            // verify correct computation of nonce_x_blind_summand (delta_i)
            // as per definition of delta_i in page 17 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            let mut nonce_x_blind_summand = r7_participant_data
                .ecdsa_nonce_summand
                .mul(&r7_participant_data.secret_blind_summand.get_element()); // k_i * gamma_i
            for (j, mta_blind_summand) in r7_participant_data.mta_blind_summands.iter().enumerate()
            {
                if j == i {
                    continue;
                }
                let mta_blind_summand = mta_blind_summand.as_ref().unwrap_or_else(|| {
                    panic!(
                        // TODO these checks should be unnecessary after refactoring
                        "r8_fail_randomizer participant {} missing mta_blind_summand from {} for {}",
                        self.my_participant_index, i, j
                    )
                });
                nonce_x_blind_summand =
                    nonce_x_blind_summand + mta_blind_summand.lhs + mta_blind_summand.rhs;
                // alpha_ij + beta_ji
            }
            let in_r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap_or_else(|| {
                panic!(
                    // TODO these checks should be unnecessary after refactoring
                    "r8_fail_randomizer participant {} missing in_r3bcast from {}",
                    self.my_participant_index, i
                )
            });
            if nonce_x_blind_summand != in_r3bcast.nonce_x_blind_summand {
                warn!(
                    "participant {} detect bad nonce_x_blind_summand from {}",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
                continue; // participant i is known to be criminal, continue to next participant
            }

            // verify r7_participant_data is consistent with earlier messages:
            // 1. ecdsa_nonce_summand (k_i)
            // 2. secret_blind_summand (gamma_i)

            // 1. ecdsa_nonce_summand (k_i)
            let ek = &self.my_secret_key_share.all_eks[self.participant_indices[i]];
            let encrypted_ecdsa_nonce_summand = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(r7_participant_data.ecdsa_nonce_summand.to_big_int()),
                &Randomness::from(&r7_participant_data.ecdsa_nonce_summand_randomness),
            );
            let in_r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap_or_else(|| {
                panic!(
                    // TODO these checks should be unnecessary after refactoring
                    "r8_fail_randomizer participant {} missing in_r1bcast from {}",
                    self.my_participant_index, i
                )
            });
            if *encrypted_ecdsa_nonce_summand.0 != in_r1bcast.encrypted_ecdsa_nonce_summand.c {
                // this code path triggered by R3BadEcdsaNonceSummand
                warn!(
                    "participant {} detect inconsistent encryption of ecdsa_nonce_summand from {}",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
                continue; // participant i is known to be criminal, continue to next participant
            }

            // 2. secret_blind_summand (gamma_i)
            let public_blind_summand = GE::generator() * r7_participant_data.secret_blind_summand;
            let in_r4bcast = self.in_r4bcasts.vec_ref()[i].as_ref().unwrap_or_else(|| {
                panic!(
                    // TODO these checks should be unnecessary after refactoring
                    "r8_fail_randomizer participant {} missing in_r4bcast from {}",
                    self.my_participant_index, i
                )
            });
            if public_blind_summand != in_r4bcast.public_blind_summand {
                // this code path triggered by R1BadSecretBlindSummand
                warn!(
                    "participant {} detect inconsistent secret_blind_summand from {}",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
                continue; // participant i is known to be criminal, continue to next participant
            }
        }

        // if no criminals were found then everyone who sent r6::Output::FailRandomizer is a criminal
        // TODO CAREFUL!  If we missed a check then a single malicious actor can cause everyone to blame everyone!
        if criminals.some_count() <= 0 {
            // TODO code copied from move_to_sad_path
            let complainers: Vec<usize> = self
                .in_r6bcasts_fail_randomizer
                .vec_ref()
                .iter()
                .enumerate()
                .filter_map(|x| if x.1.is_some() { Some(x.0) } else { None })
                .collect();
            warn!(
                "participant {} detect no fault in R7FailRandomizer; accusing complainers {:?}",
                self.my_participant_index, complainers
            );
            for c in complainers {
                criminals.overwrite(
                    c,
                    Criminal {
                        index: c,
                        crime_type: CrimeType::Malicious,
                    },
                );
            }
        }

        criminals
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
