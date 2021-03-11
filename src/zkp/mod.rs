//! Helpers for zero-knowledge range proofs
//!
//! A quick-and-dirty wrapper to clean up zkp code from https://github.com/ZenGo-X/multi-party-ecdsa
//!
//! TODO clean up: lots of repeated data
//! TODO look into the implementation here: https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs
use std::ops::Neg;

use curv::{
    arithmetic::traits::{Modulo, Samplable},
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::ECScalar,
    BigInt, FE,
};
use paillier::{
    DecryptionKey, EncryptWithChosenRandomness, EncryptionKey, KeyGeneration, Paillier, Randomness,
    RawPlaintext,
};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zkp {
    pub public: ZkpPublic, // TODO this info is already in dlog_statement
    pub dlog_statement: DLogStatement, // TODO is this necessary?
    pub dlog_proof: CompositeDLogProof, // TODO is this necessary?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkpPublic {
    n_tilde: BigInt,
    h1: BigInt,
    h2: BigInt,
    q_n_tilde: BigInt,
    q3_n_tilde: BigInt,
    q3: BigInt, // TODO this is a constant
}

impl ZkpPublic {
    // tidied version of commitment_unknown_order from multi_party_ecdsa
    pub fn commit(&self, msg: &BigInt, randomness: &BigInt) -> BigInt {
        let h1_x = BigInt::mod_pow(&self.h1, &msg, &self.n_tilde);
        let h2_r = BigInt::mod_pow(&self.h2, &randomness, &self.n_tilde);
        BigInt::mod_mul(&h1_x, &h2_r, &self.n_tilde)
    }
}

impl Zkp {
    pub fn new_unsafe() -> Self {
        Self::from_keypair(Paillier::keypair().keys())
    }

    #[allow(dead_code)] // TODO use this in production
    pub fn new() -> Self {
        Self::from_keypair(Paillier::keypair_safe_primes().keys())
    }

    pub fn from_keypair((ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey)) -> Self {
        // TODO zeroize these secrets after use
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&phi);
        let s = BigInt::from(2).pow(256_u32);
        let xhi = BigInt::sample_below(&s);
        let h2 = BigInt::mod_pow(&h1, &(-&xhi), &ek_tilde.n);

        // TODO lots of cloning here
        let dlog_statement = DLogStatement {
            N: ek_tilde.n.clone(),
            g: h1.clone(),
            ni: h2.clone(),
        };
        let dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

        let q3 = FE::q().pow(3); // TODO constant

        Self {
            public: ZkpPublic {
                h1,
                h2,
                q_n_tilde: FE::q() * &ek_tilde.n,
                q3_n_tilde: &q3 * &ek_tilde.n,
                q3,
                n_tilde: ek_tilde.n,
            },
            dlog_statement,
            dlog_proof,
        }
    }
}

pub mod range_proof;

impl Default for Zkp {
    fn default() -> Self {
        Self::new()
    }
}
