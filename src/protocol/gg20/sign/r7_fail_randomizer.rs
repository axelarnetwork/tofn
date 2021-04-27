use super::{Sign, Status};
use crate::fillvec::FillVec;
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
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
    rhs: FE,                // beta_ji
    rhs_randomness: BigInt, // beta_ji encryption randomness
    lhs: FE,                // alpha_ij
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
            mta_blind_summands
                .insert(
                    i,
                    MtaBlindSummandsData {
                        rhs: r2state.my_mta_blind_summands_rhs[i].unwrap(),
                        rhs_randomness: r2state.my_mta_blind_summands_rhs_randomness[i]
                            .as_ref()
                            .unwrap()
                            .clone(),
                        lhs: r3state.my_mta_blind_summands_lhs[i].unwrap(),
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
