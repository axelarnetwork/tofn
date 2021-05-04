use super::{crimes::Crime, Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
// use multi_party_ecdsa::utilities::mta as mta_zengo;
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};
use tracing::{error, info, warn};

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r8_fail_type7(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R7FailType7));
        assert!(self.in_r7bcasts_fail_type7.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // 'outer: for (i, r7_participant_data) in self
        for (i, r7_participant_data) in self.in_r7bcasts_fail_type7.vec_ref().iter().enumerate() {
            if r7_participant_data.is_none() {
                // this happens when parties falsely pretend 'type 7' success
                let crime = Crime::R8FailType7MissingData;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                continue; // can't proceed without data
            }
            let r7_participant_data = r7_participant_data.as_ref().unwrap();

            // verify r7_participant_data is consistent with earlier messages:
            // 1. ecdsa_nonce_summand (k_i)
            // 2. mta_wc_blind_summands.lhs (mu_ij)

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
                    "r7_fail_type5 participant {} missing in_r1bcast from {}",
                    self.my_participant_index, i
                )
            });
            if *encrypted_ecdsa_nonce_summand.0 != in_r1bcast.encrypted_ecdsa_nonce_summand.c {
                // this code path triggered by TODO
                let crime = Crime::R8FailType7BadNonceSummand;
                info!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
                // TODO continue looking for more crimes?
                // continue; // participant i is known to be criminal, continue to next participant
            }

            // 2. mta_wc_keyshare_summands.lhs (mu_ij)
            for (j, mta_wc_keyshare_summand) in r7_participant_data
                .mta_wc_keyshare_summands
                .iter()
                .enumerate()
            {
                if j == i {
                    continue;
                }
                let mta_wc_keyshare_summand = mta_wc_keyshare_summand.as_ref().unwrap_or_else(|| {
                    panic!(
                        // TODO these checks should be unnecessary after refactoring
                        "r8_fail_type7 participant {} missing mta_wc_keyshare_summand belonging to {} from {}",
                        self.my_participant_index, i, j
                    )
                });
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
                        .mta_response_keyshare
                        .c
                {
                    // this code path triggered by TODO

                    // It's getting intractable to write tests for malicious behaviour.  Example: I want to corrupt `mu_ij` to trigger `Crime::R8FailType7MtaWcKeyshareSummandLhs`.  This requires corrupting `mu_ij`, `sigma_i`, and the Pedersen commitment and zk proof for `sigma_i` in round 3.  It's relatively easy to corrupt `mu_ij`, `sigma_i` after-the-fact like we've always done, but the only way to also corrupt the Pedersen commitment and zk proof we need to re-run `pedersen::commit` AND `pedersen::prove` after-the-fact.  At this point we're basically re-executing round 3 in the malicious code---it's no longer tractable to corrupt after-the-fact.  Instead, I need to re-design the codebase to facilitate corruption inside honest code.

                    let crime = Crime::R8FailType7MtaWcKeyshareSummandLhs { victim: j };
                    info!(
                        "participant {} detect {:?} (mu_ij) by {}",
                        self.my_participant_index, crime, i
                    );
                    criminals[i].push(crime);
                    // TODO continue looking for more crimes?
                    // continue 'outer; // participant i is known to be criminal, continue to next participant
                }
            }

            // DONE TO HERE
            todo!()
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
