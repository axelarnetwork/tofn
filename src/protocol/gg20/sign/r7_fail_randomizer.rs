use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
    zkp::range,
};
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use log::warn;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastRandomizer {
    // TODO do I also need encryption randomness for alpha_ij ?  Yes.
    // get encryption randomness for alpha_ij from Paillier::open
    // how to verify integrity of alpha_ij, beta_ji:
    // 1. call MessageB::b_with_predefined_randomness to get enc(alpha_ji) and beta_ji
    // 2. call Paillier::encrypt_with_chosen_randomness to get enc(alpha_ji)
    pub ecdsa_nonce_summand: FE,                // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
    pub secret_blind_summand: FE,               // gamma_i

    // make this one vec of a struct
    pub mta_blind_summands_rhs: Vec<Option<FE>>, // beta_ji
    pub mta_blind_summands_rhs_randomness: Vec<Option<BigInt>>, // beta_ji encryption randomness
    pub mta_blind_summands_lhs: Vec<Option<FE>>, // alpha_ij
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r7_fail_randomizer(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R6FailRandomizer));
        assert!(self.in_r6bcasts_fail_randomizer.some_count() > 0);

        let mut culprits = FillVec::with_len(self.participant_indices.len());

        for (i, r6_participant_data) in self
            .in_r6bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r6_participant_data.is_none() {
                warn!(
                    "participant {} says: missing R6FailRandomizer data from participant {}",
                    self.my_participant_index, i
                );
                continue;
            }
            // DONE TO HERE
        }

        // let r1state = self.r1state.as_ref().unwrap();
        // let r2state = self.r2state.as_ref().unwrap();
        // let r3state = self.r3state.as_ref().unwrap();
        // out_bcast: BcastRandomizer {
        //     ecdsa_nonce_summand: r1state.my_ecdsa_nonce_summand,
        //     ecdsa_nonce_summand_randomness: r1state
        //         .my_encrypted_ecdsa_nonce_summand_randomness
        //         .clone(),
        //     secret_blind_summand: r1state.my_secret_blind_summand,
        //     mta_blind_summands_rhs: r2state.my_mta_blind_summands_rhs.clone(),
        //     mta_blind_summands_rhs_randomness: r2state
        //         .my_mta_blind_summands_rhs_randomness
        //         .clone(),
        //     mta_blind_summands_lhs: r3state.my_mta_blind_summands_lhs.clone(),
        // },

        culprits
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
