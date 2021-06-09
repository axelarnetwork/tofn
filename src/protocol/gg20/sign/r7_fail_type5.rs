use super::{crimes::Crime, Sign, Status};
use crate::mta;
use crate::paillier_k256::Plaintext;
use tracing::{error, info, warn};

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    #[allow(non_snake_case)]
    pub(super) fn r7_fail_type5(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R6FailType5));
        assert!(self.in_r6bcasts_fail_type5.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // 'outer: for (i, r7_participant_data) in self
        for (i, r6_participant_data) in self.in_r6bcasts_fail_type5.vec_ref().iter().enumerate() {
            if r6_participant_data.is_none() {
                // this happens when parties falsely pretend 'type 5' success
                let crime = Crime::R7FailType5MissingData;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                continue; // can't proceed without data
            }
            let r6_participant_data = r6_participant_data.as_ref().unwrap();

            // verify correct computation of delta_i
            // as per page 17 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            let in_r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap();
            let delta_i_k256 = {
                let mut sum = r6_participant_data.k_i_256.unwrap()
                    * r6_participant_data.gamma_i_k256.unwrap();
                for (j, mta_plaintext) in r6_participant_data.mta_plaintexts.iter().enumerate() {
                    if j == i {
                        continue;
                    }
                    let mta_plaintext = mta_plaintext.as_ref().unwrap();
                    let alpha_k256 = mta_plaintext.alpha_plaintext_k256.to_scalar();
                    sum = sum + alpha_k256 + mta_plaintext.beta_secrets_k256.beta.unwrap();
                }
                sum
            };
            if delta_i_k256 != *in_r3bcast.delta_i_k256.unwrap() {
                let crime = Crime::R7FailType5BadDeltaI;
                info!(
                    "(k256) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes by this participant?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // verify r7_participant_data is consistent with earlier messages:
            // 1. k_i
            // 2. gamma_i
            // 3. beta_ij
            // 4. alpha_ij
            let in_r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();
            let ek_k256 = &self.my_secret_key_share.group.all_eks_k256[self.participant_indices[i]];

            // k_i
            let k_i_ciphertext_k256 = ek_k256.encrypt_with_randomness(
                &Plaintext::from_scalar(r6_participant_data.k_i_256.unwrap()),
                &r6_participant_data.k_i_randomness_k256,
            );
            if k_i_ciphertext_k256 != in_r1bcast.k_i_ciphertext_k256 {
                let crime = Crime::R7FailType5BadKI;
                info!(
                    "(k256) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // gamma_i
            let Gamma_i_k256 =
                k256::ProjectivePoint::generator() * r6_participant_data.gamma_i_k256.unwrap();
            let in_r4bcast = self.in_r4bcasts.vec_ref()[i].as_ref().unwrap();
            if Gamma_i_k256 != *in_r4bcast.Gamma_i_k256.unwrap() {
                let crime = Crime::R7FailType5BadGammaI;
                info!(
                    "(k256) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // beta_ij, alpha_ij
            for (j, mta_plaintext) in r6_participant_data.mta_plaintexts.iter().enumerate() {
                if j == i {
                    continue;
                }
                let mta_plaintext = mta_plaintext.as_ref().unwrap();

                // beta_ij
                let other_ek_k256 =
                    &self.my_secret_key_share.group.all_eks_k256[self.participant_indices[j]];
                let other_k_i_ciphertext_k256 = &self.in_r1bcasts.vec_ref()[j]
                    .as_ref()
                    .unwrap()
                    .k_i_ciphertext_k256;
                let other_alpha_ciphertext = &self.in_all_r2p2ps[i].vec_ref()[j]
                    .as_ref()
                    .unwrap()
                    .alpha_ciphertext_k256;
                if !mta::verify_mta_response(
                    other_ek_k256,
                    &other_k_i_ciphertext_k256,
                    r6_participant_data.gamma_i_k256.unwrap(),
                    other_alpha_ciphertext,
                    &mta_plaintext.beta_secrets_k256,
                ) {
                    let crime = Crime::R7FailType5BadBeta { victim: j };
                    info!(
                        "(k256) participant {} detect {:?} (beta_ji) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                    // TODO continue looking for more crimes?
                    // continue 'outer; // participant i is known to be criminal, continue to next participant
                }

                // alpha_ij
                let alpha_ciphertext_k256 = ek_k256.encrypt_with_randomness(
                    &mta_plaintext.alpha_plaintext_k256,
                    &mta_plaintext.alpha_randomness_k256,
                );
                if alpha_ciphertext_k256
                    != self.in_all_r2p2ps[j].vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .alpha_ciphertext_k256
                {
                    let crime = Crime::R7FailType5BadAlpha { victim: j };
                    info!(
                        "(k256) participant {} detect {:?} (alpha_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                    // TODO continue looking for more crimes?
                    // continue 'outer; // participant i is known to be criminal, continue to next participant
                }
            }
        }

        if criminals.iter().all(Vec::is_empty) {
            error!(
                "participant {} detect 'type 5' fault but found no criminals",
                self.my_participant_index,
            );
        }
        criminals
    }
}
