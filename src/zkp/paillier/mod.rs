//! Helpers for zero-knowledge range proofs
//!
//! A quick-and-dirty wrapper to clean up zkp code from https://github.com/ZenGo-X/multi-party-ecdsa
//!
//! TODO clean up: lots of repeated data
//! TODO look into the implementation here: https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs

use curv::{
    arithmetic::traits::{Modulo, Samplable},
    elliptic::curves::traits::ECScalar,
    BigInt, FE,
};
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

pub mod mta;
pub mod range;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkSetup {
    composite_dlog_statement: DLogStatement,
    composite_dlog_proof: CompositeDLogProof,
    q_n_tilde: BigInt,
    q3_n_tilde: BigInt,
    q3: BigInt, // TODO constant
}

impl ZkSetup {
    pub fn new_unsafe() -> Self {
        Self::from_keypair(Paillier::keypair().keys())
    }

    #[allow(dead_code)] // TODO use this in production
    pub fn new() -> Self {
        Self::from_keypair(Paillier::keypair_safe_primes().keys())
    }

    fn from_keypair((ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey)) -> Self {
        // TODO constants
        let one = BigInt::one();
        let s = BigInt::from(2).pow(256_u32);

        // TODO zeroize these secrets after use
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let xhi = BigInt::sample_below(&s);

        let h1 = BigInt::sample_below(&phi);
        let h2 = BigInt::mod_pow(&h1, &(-&xhi), &ek_tilde.n);

        let dlog_statement = DLogStatement {
            N: ek_tilde.n, // n_tilde
            g: h1,         // h1
            ni: h2,        // h2
        };
        let dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

        let q3 = FE::q().pow(3); // TODO constant
        Self {
            q_n_tilde: FE::q() * &dlog_statement.N,
            q3_n_tilde: &q3 * &dlog_statement.N,
            q3,
            composite_dlog_statement: dlog_statement,
            composite_dlog_proof: dlog_proof,
        }
    }

    fn h1(&self) -> &BigInt {
        &self.composite_dlog_statement.g
    }
    fn h2(&self) -> &BigInt {
        &self.composite_dlog_statement.ni
    }
    fn n_tilde(&self) -> &BigInt {
        &self.composite_dlog_statement.N
    }
    // tidied version of commitment_unknown_order from multi_party_ecdsa
    fn commit(&self, msg: &BigInt, randomness: &BigInt) -> BigInt {
        let h1_x = BigInt::mod_pow(self.h1(), &msg, self.n_tilde());
        let h2_r = BigInt::mod_pow(self.h2(), &randomness, self.n_tilde());
        BigInt::mod_mul(&h1_x, &h2_r, self.n_tilde())
    }

    pub fn verify_composite_dlog_proof(&self) -> bool {
        self.composite_dlog_proof
            .verify(&self.composite_dlog_statement)
            .is_ok()
    }
}

// clippy appeasement
impl Default for ZkSetup {
    fn default() -> Self {
        Self::new()
    }
}
