use super::{r2, Sign, Status};
use crate::fillvec::FillVec;
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE};
use paillier::{
    // DecryptionKey, EncryptionKey, Open, Paillier, Randomness, RawCiphertext, RawPlaintext,
    Open,
    Paillier,
    RawCiphertext,
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    // TODO do I also need encryption randomness for alpha_ij ?  Yes.
    // get encryption randomness for alpha_ij from Paillier::open
    // how to verify integrity of alpha_ij, beta_ji:
    // 1. call MessageB::b_with_predefined_randomness to get enc(alpha_ji) and beta_ji
    // 2. call Paillier::encrypt_with_chosen_randomness to get enc(alpha_ji)
    pub ecdsa_nonce_summand: FE,                // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
    pub secret_blind_summand: FE,               // gamma_i
    pub mta_blind_summands: Vec<Option<MtaBlindSummandsData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaBlindSummandsData {
    pub(super) rhs: FE,                           // beta_ji
    pub(super) rhs_randomness: r2::RhsRandomness, // beta_ji encryption randomness
    pub(super) lhs_plaintext: BigInt,             // alpha_ij Paillier plaintext
    pub(super) lhs_randomness: BigInt,            // alpha_ij encryption randomness
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r7_fail_randomizer(&self) -> Bcast {
        assert!(matches!(self.status, Status::R6FailRandomizer));
        assert!(self.in_r6bcasts_fail_randomizer.some_count() > 0);

        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let mut mta_blind_summands = FillVec::with_len(self.participant_indices.len());

        for i in 0..self.participant_indices.len() {
            if i == self.my_participant_index {
                continue;
            }

            // recover encryption randomness for my_mta_blind_summands_lhs
            // need to decrypt again to do so
            let in_p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap_or_else(|| {
                    // TODO these checks should not be necessary after refactoring
                    panic!(
                        "r7_fail_randomizer participant {} says: missing r2p2p from {}",
                        self.my_participant_index, i
                    )
                });
            let (my_mta_blind_summand_lhs_plaintext, my_mta_blind_summand_lhs_randomness) =
                Paillier::open(
                    &self.my_secret_key_share.my_dk,
                    &RawCiphertext::from(&in_p2p.mta_response_blind.c),
                );

            // sanity check: we should recover the value we computed in r3
            {
                let my_mta_blind_summand_lhs_mod_q: FE =
                    ECScalar::from(&my_mta_blind_summand_lhs_plaintext.0);
                assert_eq!(
                    my_mta_blind_summand_lhs_mod_q,
                    r3state.my_mta_blind_summands_lhs[i].unwrap(),
                    "participant {}: decryption of mta_response_blind from {} in r7_fail_randomizer differs from r3", self.my_participant_index, i
                ); // TODO panic

                // do not return my_mta_blind_summand_lhs_mod_q
                // need my_mta_blind_summand_lhs_plaintext because it may differ from my_mta_blind_summand_lhs_mod_q
                // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting my_mta_blind_summand_lhs_mod_q
            }

            mta_blind_summands
                .insert(
                    i,
                    MtaBlindSummandsData {
                        rhs: r2state.my_mta_blind_summands_rhs[i].unwrap(),
                        rhs_randomness: r2state.my_mta_blind_summands_rhs_randomness[i]
                            .as_ref()
                            .unwrap()
                            .clone(),
                        lhs_plaintext: (*my_mta_blind_summand_lhs_plaintext.0).clone(),
                        lhs_randomness: my_mta_blind_summand_lhs_randomness.0,
                    },
                )
                .unwrap();
        }

        Bcast {
            ecdsa_nonce_summand: r1state.my_ecdsa_nonce_summand,
            ecdsa_nonce_summand_randomness: r1state
                .my_encrypted_ecdsa_nonce_summand_randomness
                .clone(),
            secret_blind_summand: r1state.my_secret_blind_summand,
            mta_blind_summands: mta_blind_summands.into_vec(),
        }
    }
}
