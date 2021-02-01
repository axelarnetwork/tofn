pub mod r1;

use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::protocol::gg20::keygen::SecretKeyShare;
// round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1Bcast {
    my_commit: BigInt,
}
pub struct R1P2p {
    my_encrypted_ecdsa_nonce_summand: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct R1State {
    // key: SecretKeyShare,
    my_secret_key_summand: FE,
    my_ecdsa_nonce_summand: FE,
    // my_commit: BigInt, // for convenience: a copy of R1Bcast.commit
    my_reveal: BigInt, // decommit---to be released later
    my_encrypted_ecdsa_nonce_summand_randomnesses: Vec<Option<Randomness>>, // TODO do we need to store this?
}

// #[cfg(test)]
// mod tests;
