use serde::{Deserialize, Serialize};

use crate::crypto_tools::{k256_serde, paillier, zkp::chaum_pedersen};

mod happy;
pub(super) use happy::R7Happy;
mod sad;
pub(super) use sad::R7Sad;
mod type5;
pub(super) use type5::R7Type5;
mod common;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    SadType7(BcastSadType7),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub s_i: k256_serde::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSadType7 {
    pub(super) k_i: k256_serde::Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) proof: chaum_pedersen::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    // mu_plaintext instead of mu
    // because mu_plaintext may differ from mu
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting mu
    pub(super) mu_plaintext: paillier::Plaintext,
    pub(super) mu_randomness: paillier::Randomness,
}
