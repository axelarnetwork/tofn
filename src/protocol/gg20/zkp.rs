//! Helpers for zero-knowledge range proofs
//! 
//! A quick-and-dirty wrapper to clean up zkp code from https://github.com/ZenGo-X/multi-party-ecdsa
//! 
//! TODO clean up: lots of repeated data
//! TODO look into the implementation here: https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs
use serde::{Deserialize, Serialize};
use curv::{
    BigInt,
    arithmetic::traits::{Samplable, Modulo},
};
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zkp {
    pub public: ZkpPublic, // TODO this info is already in dlog_statement
    pub dlog_statement: DLogStatement,
    pub dlog_proof: CompositeDLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkpPublic {
    n_tilde: BigInt,
    h1 : BigInt,
    h2 : BigInt,
}

impl Zkp {
    pub fn new_unsafe() -> Self {
        Self::from_keypair( Paillier::keypair().keys() )
    }

    #[allow(dead_code)] // TODO use this in production
    pub fn new() -> Self {
        Self::from_keypair( Paillier::keypair_safe_primes().keys() )
    }

    pub fn from_keypair((ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey)) -> Self {

        // TODO zeroize these secrets after use
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&phi);
        let s = BigInt::from(2).pow(256 as u32);
        let xhi = BigInt::sample_below(&s);
        let h2 = BigInt::mod_pow(&h1, &(-&xhi), &ek_tilde.n);

        // TODO lots of cloning here
        let dlog_statement = DLogStatement {
            N: ek_tilde.n.clone(),
            g: h1.clone(),
            ni: h2.clone(),
        };
        let dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

        Self {
            public: ZkpPublic {
                n_tilde: ek_tilde.n,
                h1,
                h2,
            },
            dlog_statement,
            dlog_proof,
        }
    }
}
