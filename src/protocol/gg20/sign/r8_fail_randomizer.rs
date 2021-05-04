use super::{crimes::Crime, Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use multi_party_ecdsa::utilities::mta as mta_zengo;
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};
use tracing::{error, info, warn};

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r7_fail_randomizer(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R6FailRandomizer));
        assert!(self.in_r6bcasts_fail_randomizer.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // 'outer: for (i, r7_participant_data) in self
        for (i, r6_participant_data) in self
            .in_r6bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r6_participant_data.is_none() {
                // this happens when parties falsely pretend 'type 5' success
                let crime = Crime::R7FailRandomizerMissingData;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                continue; // can't proceed without data
            }
            let r6_participant_data = r6_participant_data.as_ref().unwrap();

            // verify correct computation of nonce_x_blind_summand (delta_i)
            // as per definition of delta_i in page 17 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            let mut nonce_x_blind_summand = r6_participant_data
                .ecdsa_nonce_summand
                .mul(&r6_participant_data.secret_blind_summand.get_element()); // k_i * gamma_i
            for (j, mta_blind_summand) in r6_participant_data.mta_blind_summands.iter().enumerate()
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
                let my_mta_blind_summand_lhs_mod_q: FE =
                    ECScalar::from(&mta_blind_summand.lhs_plaintext);
                nonce_x_blind_summand =
                    nonce_x_blind_summand + my_mta_blind_summand_lhs_mod_q + mta_blind_summand.rhs;
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
                let crime = Crime::R7FailRandomizerBadNonceXBlindSummand;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // verify r7_participant_data is consistent with earlier messages:
            // 1. ecdsa_nonce_summand (k_i)
            // 2. secret_blind_summand (gamma_i)
            // 3. mta_blind_summands.rhs (beta_ij)
            // 4. mta_blind_summands.lhs (alpha_ij)

            // 1. ecdsa_nonce_summand (k_i)
            let ek = &self.my_secret_key_share.all_eks[self.participant_indices[i]];
            let encrypted_ecdsa_nonce_summand = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(r6_participant_data.ecdsa_nonce_summand.to_big_int()),
                &Randomness::from(&r6_participant_data.ecdsa_nonce_summand_randomness),
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
                let crime = Crime::R7FailRandomizerBadNonceSummand;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // 2. secret_blind_summand (gamma_i)
            let public_blind_summand = GE::generator() * r6_participant_data.secret_blind_summand;
            let in_r4bcast = self.in_r4bcasts.vec_ref()[i].as_ref().unwrap_or_else(|| {
                panic!(
                    // TODO these checks should be unnecessary after refactoring
                    "r8_fail_randomizer participant {} missing in_r4bcast from {}",
                    self.my_participant_index, i
                )
            });
            if public_blind_summand != in_r4bcast.public_blind_summand {
                // this code path triggered by R1BadSecretBlindSummand
                let crime = Crime::R7FailRandomizerBadBlindSummand;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // 3. mta_blind_summands.rhs (beta_ij)
            // 4. mta_blind_summands.lhs (alpha_ij)
            for (j, mta_blind_summand) in r6_participant_data.mta_blind_summands.iter().enumerate()
            {
                if j == i {
                    continue;
                }
                let mta_blind_summand = mta_blind_summand.as_ref().unwrap_or_else(|| {
                    panic!(
                        // TODO these checks should be unnecessary after refactoring
                        "r8_fail_randomizer participant {} missing mta_blind_summand belonging to {} from {}",
                        self.my_participant_index, i, j
                    )
                });

                // 3. mta_blind_summands.rhs (beta_ij)
                let other_ek = &self.my_secret_key_share.all_eks[self.participant_indices[j]];
                let other_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()[j]
                    .as_ref()
                    .unwrap()
                    .encrypted_ecdsa_nonce_summand;
                // TODO better variable names: switch to greek letters used in GG20 paper
                let (mta_response_blind, mta_blind_summand_rhs) = // (enc(alpha_ij), beta_ji)
                    mta_zengo::MessageB::b_with_predefined_randomness(
                        &r6_participant_data.secret_blind_summand,
                        other_ek,
                        other_encrypted_ecdsa_nonce_summand.clone(),
                        &mta_blind_summand.rhs_randomness.randomness,
                        &mta_blind_summand.rhs_randomness.beta_prime,
                    );
                if mta_blind_summand_rhs != mta_blind_summand.rhs
                    || mta_response_blind.c
                        != self.in_all_r2p2ps[i].vec_ref()[j]
                            .as_ref()
                            .unwrap()
                            .mta_response_blind
                            .c
                {
                    // this code path triggered by R3BadMtaBlindSummandRhs
                    let crime = Crime::R7FailRandomizerMtaBlindSummandRhs { victim: j };
                    info!(
                        "participant {} detect {:?} (beta_ji) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                    // TODO continue looking for more crimes?
                    // continue 'outer; // participant i is known to be criminal, continue to next participant
                }

                // 4. mta_blind_summands.lhs (alpha_ij)
                let mta_blind_summand_lhs_ciphertext = Paillier::encrypt_with_chosen_randomness(
                    ek,
                    RawPlaintext::from(&mta_blind_summand.lhs_plaintext),
                    &Randomness::from(&mta_blind_summand.lhs_randomness),
                );
                if *mta_blind_summand_lhs_ciphertext.0
                    != self.in_all_r2p2ps[j].vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .mta_response_blind
                        .c
                {
                    // this code path triggered by R3BadMtaBlindSummandLhs
                    let crime = Crime::R7FailRandomizerMtaBlindSummandLhs { victim: j };
                    info!(
                        "participant {} detect {:?} (alpha_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                    // TODO continue looking for more crimes?
                    // continue 'outer; // participant i is known to be criminal, continue to next participant
                }
            }
        }

        if criminals.iter().map(|v| v.len()).sum::<usize>() == 0 {
            error!(
                "participant {} detect 'type 5' fault but found no criminals",
                self.my_participant_index,
            );
        }
        criminals
    }
}
