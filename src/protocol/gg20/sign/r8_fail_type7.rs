use super::{crimes::Crime, is_empty, r7, Sign, Status};
use crate::zkp::chaum_pedersen;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};
use tracing::{error, info, warn};

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r8_fail_type7(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R7FailType7));
        assert!(self.in_r7bcasts_fail_type7.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // any participant who did not send data is a criminal
        for (i, data) in self.in_r7bcasts_fail_type7.vec_ref().iter().enumerate() {
            if data.is_none() {
                // this happens when parties falsely pretend 'type 7' success
                let crime = Crime::R8FailType7MissingData;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }
        }
        // can't proceed without everyone's data
        if !is_empty(&criminals) {
            return criminals;
        }
        // now we can safely unwrap everyone's data
        let all_r7bcasts: Vec<&r7::BcastFailType7> = self
            .in_r7bcasts_fail_type7
            .vec_ref()
            .iter()
            .map(|x| x.as_ref().unwrap())
            .collect();

        // verify that each participant's data is consistent with earlier messages:
        // 1. ecdsa_nonce_summand (k_i)
        // 2. mta_wc_blind_summands.lhs (mu_ij)
        for (i, r7bcast) in all_r7bcasts.iter().enumerate() {
            // 1. ecdsa_nonce_summand (k_i)
            let ek = &self.my_secret_key_share.all_eks[self.participant_indices[i]];
            let encrypted_ecdsa_nonce_summand = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(r7bcast.ecdsa_nonce_summand.to_big_int()),
                &Randomness::from(&r7bcast.ecdsa_nonce_summand_randomness),
            );
            let in_r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();
            if *encrypted_ecdsa_nonce_summand.0 != in_r1bcast.k_i_ciphertext.c {
                // this code path triggered by TODO
                let crime = Crime::R8FailType7BadNonceSummand;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }

            // 2. mta_wc_keyshare_summands.lhs (mu_ij)
            for (j, mta_wc_keyshare_summand) in r7bcast.mta_wc_keyshare_summands.iter().enumerate()
            {
                if j == i {
                    continue;
                }
                let mta_wc_keyshare_summand = mta_wc_keyshare_summand.as_ref().unwrap();
                let mta_wc_keyshare_summand_lhs_ciphertext =
                    Paillier::encrypt_with_chosen_randomness(
                        ek,
                        RawPlaintext::from(&mta_wc_keyshare_summand.lhs_plaintext),
                        &Randomness::from(&mta_wc_keyshare_summand.lhs_randomness),
                    );
                if *mta_wc_keyshare_summand_lhs_ciphertext.0
                    != self.in_all_r2p2ps[j].vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .mu_ciphertext
                        .c
                {
                    // this code path triggered by TODO
                    let crime = Crime::R8FailType7MtaWcKeyshareSummandLhs { victim: j };
                    info!(
                        "participant {} detect {:?} (mu_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                }
            }
        }

        // compute ecdsa nonce k = sum_i k_i
        let zero: FE = ECScalar::zero();
        let ecdsa_nonce = all_r7bcasts
            .iter()
            .fold(zero, |acc, b| acc + b.ecdsa_nonce_summand);

        // verify zkps as per page 19 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
        for (i, r7bcast) in all_r7bcasts.iter().enumerate() {
            // compute sigma_i * G as per the equation at the bottom of page 18 of
            // https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431

            // BEWARE: there is a typo in the equation second from the bottom of page 18 of
            // https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            // the subscripts of nu should be reversed: nu_ji -> nu_ij

            // the formula for sigma_i simplifies to the following:
            //   sigma_i = w_i * k + sum_{j!=i} (mu_ij - mu_ji)
            // thus we may compute sigma_i * G as follows:
            //   k * W_i + sum_{j!=i} (mu_ij - mu_ji) * G

            // compute sum_{j!=i} (mu_ij - mu_ji)
            let mu_summation = r7bcast.mta_wc_keyshare_summands.iter().enumerate().fold(
                zero,
                |acc, (j, summand)| {
                    if j == i {
                        acc
                    } else {
                        let mu_ij: FE = ECScalar::from(&summand.as_ref().unwrap().lhs_plaintext);
                        let mu_ji: FE = ECScalar::from(
                            &all_r7bcasts[j].mta_wc_keyshare_summands[i]
                                .as_ref()
                                .unwrap()
                                .lhs_plaintext,
                        );
                        let neg_mu_ji: FE = zero.sub(&mu_ji.get_element()); // wow zengo sucks
                        acc + mu_ij + neg_mu_ji
                    }
                },
            );

            chaum_pedersen::verify(
                &chaum_pedersen::Statement {
                    base1: &GE::generator(),                  // G
                    base2: &self.r5state.as_ref().unwrap().R, // R
                    target1: &(self.public_key_summand(i) * ecdsa_nonce
                        + (GE::generator() * mu_summation)), // sigma_i * G
                    target2: &self.in_r6bcasts.vec_ref()[i].as_ref().unwrap().S_i, // sigma_i * R == S_i
                },
                &r7bcast.proof,
            )
            .unwrap_or_else(|e| {
                let crime = Crime::R8FailType7BadZkp;
                warn!(
                    "participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });
        }

        if is_empty(&criminals) {
            error!(
                "participant {} detect 'type 7' fault but found no criminals",
                self.my_participant_index,
            );
        }
        criminals
    }
}
