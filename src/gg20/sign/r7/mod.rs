use serde::{Deserialize, Serialize};

use crate::{
    collections::HoleVecMap,
    gg20::crypto_tools::{k256_serde, paillier, zkp::chaum_pedersen_k256},
};

use super::SignShareId;

pub mod happy;
pub mod sad;
pub mod type5;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub s_i: k256_serde::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub k_i: k256_serde::Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub proof: chaum_pedersen_k256::Proof,
    pub mta_wc_plaintexts: HoleVecMap<SignShareId, MtaWcPlaintext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaWcPlaintext {
    // mu_plaintext instead of mu
    // because mu_plaintext may differ from mu
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting mu
    pub mu_plaintext: paillier::Plaintext,
    pub mu_randomness: paillier::Randomness,
}
