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

    // statement (ciphertext, ek), witness (msg, randomness)
    //   such that ciphertext = Enc(ek, msg, randomness) and -q^3 < msg < q^3
    // See appendix A.1 of https://eprint.iacr.org/2019/114.pdf
    // Used by Alice in the first message of MtA
    #[allow(clippy::many_single_char_names)]
    pub fn range_proof(&self, stmt: &RangeStatement, wit: &RangeWitness) -> RangeProof {
        let alpha = BigInt::sample_below(&self.public.q3);
        let beta = Randomness::sample(&stmt.ek); // TODO sample() may not be coprime to stmt.ek.n; do we care?
        let rho = BigInt::sample_below(&self.public.q_n_tilde);
        let gamma = BigInt::sample_below(&self.public.q3_n_tilde);

        let z = self.public.commit(&wit.msg.to_big_int(), &rho);
        let u =
            Paillier::encrypt_with_chosen_randomness(stmt.ek, RawPlaintext::from(&alpha), &beta)
                .0
                .clone()
                .into_owned(); // TODO wtf clone into_owned why does paillier suck so bad?
        let w = self.public.commit(&alpha, &gamma);

        let e = HSha256::create_hash(&[
            &stmt.ek.n,
            // TODO add stmt.ek.gamma to this hash like binance? zengo puts a bunch of other crap in here
            &stmt.ciphertext,
            &z,
            &u,
            &w,
        ])
        .modulus(&FE::q());

        let s = BigInt::mod_mul(
            &BigInt::mod_pow(&wit.randomness, &e, &stmt.ek.n),
            &beta.0,
            &stmt.ek.n,
        );
        let s1 = &e * wit.msg.to_big_int() + alpha;
        let s2 = e * rho + gamma;

        RangeProof { z, u, w, s, s1, s2 }
    }

    pub fn verify_range_proof(&self, stmt: &RangeStatement, proof: &RangeProof) -> Result<(), ()> {
        if proof.s1 > self.public.q3 || proof.s1 < BigInt::zero() {
            return Err(());
        }
        let e_neg =
            HSha256::create_hash(&[&stmt.ek.n, &stmt.ciphertext, &proof.z, &proof.u, &proof.w])
                .modulus(&FE::q())
                .neg();
        let u_check = BigInt::mod_mul(
            &Paillier::encrypt_with_chosen_randomness(
                stmt.ek,
                RawPlaintext::from(&proof.s1),
                &Randomness::from(&proof.s),
            )
            .0,
            &BigInt::mod_pow(&stmt.ciphertext, &e_neg, &stmt.ek.nn),
            &stmt.ek.nn,
        );
        if u_check != proof.u {
            return Err(());
        }
        let w_check = BigInt::mod_mul(
            &self.public.commit(&proof.s1, &proof.s2),
            &BigInt::mod_pow(&proof.z, &e_neg, &self.public.n_tilde),
            &self.public.n_tilde,
        );
        if w_check != proof.w {
            return Err(());
        }
        Ok(())
    }
}

pub struct RangeStatement<'a> {
    pub ciphertext: &'a BigInt,
    pub ek: &'a EncryptionKey,
}
pub struct RangeWitness<'a> {
    pub msg: &'a FE,
    pub randomness: &'a BigInt, // TODO use Paillier::Ransomness instead?
}

pub struct RangeProof {
    z: BigInt,
    u: BigInt, // TODO use Paillier::RawCiphertext instead?
    w: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

#[cfg(test)]
mod tests;
