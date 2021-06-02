use super::{crimes::Crime, r7, Sign, Status};
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
        if !criminals.iter().all(Vec::is_empty) {
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
            let in_r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();

            // curv: 1. k_i
            let ek = &self.my_secret_key_share.all_eks[self.participant_indices[i]];
            let k_i_ciphertext = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(r7bcast.k_i.to_big_int()),
                &Randomness::from(&r7bcast.k_i_randomness),
            );
            if *k_i_ciphertext.0 != in_r1bcast.k_i_ciphertext.c {
                // this code path triggered by TODO
                let crime = Crime::R8FailType7BadKI;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }

            // k256: 1. k_i
            let ek_k256 = &self.my_secret_key_share.all_eks_k256[self.participant_indices[i]];
            let k_i_ciphertext_k256 = ek_k256.encrypt_with_randomness(
                &r7bcast.k_i_k256.unwrap().into(),
                &r7bcast.k_i_randomness_k256,
            );
            if k_i_ciphertext_k256 != in_r1bcast.k_i_ciphertext_k256 {
                let crime = Crime::R8FailType7BadKI;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }

            // curv: 2. mu_ij
            for (j, mta_wc_plaintext) in r7bcast.mta_wc_plaintexts.iter().enumerate() {
                if j == i {
                    continue;
                }
                let mta_wc_plaintext = mta_wc_plaintext.as_ref().unwrap();
                let mu_ciphertext = Paillier::encrypt_with_chosen_randomness(
                    ek,
                    RawPlaintext::from(&mta_wc_plaintext.mu_plaintext),
                    &Randomness::from(&mta_wc_plaintext.mu_randomness),
                );
                if *mu_ciphertext.0
                    != self.in_all_r2p2ps[j].vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .mu_ciphertext
                        .c
                {
                    // this code path triggered by TODO
                    let crime = Crime::R8FailType7BadMu { victim: j };
                    info!(
                        "participant {} detect {:?} (mu_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                }
            }

            // k256: 2. mu_ij
            for (j, mta_wc_plaintext) in r7bcast.mta_wc_plaintexts.iter().enumerate() {
                if j == i {
                    continue;
                }
                let mta_wc_plaintext = mta_wc_plaintext.as_ref().unwrap();
                let mu_ciphertext_k256 = ek_k256.encrypt_with_randomness(
                    &mta_wc_plaintext.mu_plaintext_k256,
                    &mta_wc_plaintext.mu_randomness_k256,
                );
                if mu_ciphertext_k256
                    != self.in_all_r2p2ps[j].vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .mu_ciphertext_k256
                {
                    let crime = Crime::R8FailType7BadMu { victim: j };
                    info!(
                        "participant {} detect {:?} (mu_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                }
            }
        }

        // DONE TO HERE

        // compute ecdsa nonce k = sum_i k_i
        let zero: FE = ECScalar::zero();
        let ecdsa_nonce = all_r7bcasts.iter().fold(zero, |acc, b| acc + b.k_i);

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
            let mu_summation =
                r7bcast
                    .mta_wc_plaintexts
                    .iter()
                    .enumerate()
                    .fold(zero, |acc, (j, summand)| {
                        if j == i {
                            acc
                        } else {
                            let mu_ij: FE = ECScalar::from(&summand.as_ref().unwrap().mu_plaintext);
                            let mu_ji: FE = ECScalar::from(
                                &all_r7bcasts[j].mta_wc_plaintexts[i]
                                    .as_ref()
                                    .unwrap()
                                    .mu_plaintext,
                            );
                            let neg_mu_ji: FE = zero.sub(&mu_ji.get_element()); // wow zengo sucks
                            acc + mu_ij + neg_mu_ji
                        }
                    });

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

        if criminals.iter().all(Vec::is_empty) {
            error!(
                "participant {} detect 'type 7' fault but found no criminals",
                self.my_participant_index,
            );
        }
        criminals
    }
}
