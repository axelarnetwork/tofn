use std::ops::Neg;

use crate::zkp::Zkp;
use curv::{
    arithmetic::traits::{Modulo, Samplable},
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub ciphertext: &'a BigInt,
    pub ek: &'a EncryptionKey,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub msg: &'a FE,
    pub randomness: &'a BigInt, // TODO use Paillier::Ransomness instead?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    z: BigInt,
    u: BigInt, // TODO use Paillier::RawCiphertext instead?
    w: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

#[derive(Clone, Debug)]
pub struct StatementWc<'a> {
    pub stmt: Statement<'a>,
    pub msg_g: &'a GE,
    pub g: &'a GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWc {
    proof: Proof,
    u1: GE,
}

impl Zkp {
    // statement (ciphertext, ek), witness (msg, randomness)
    //   such that ciphertext = Enc(ek, msg, randomness) and -q^3 < msg < q^3
    // full specification: appendix A.1 of https://eprint.iacr.org/2019/114.pdf
    pub fn range_proof(&self, stmt: &Statement, wit: &Witness) -> Proof {
        self.range_proof_inner(stmt, None, wit).0
    }

    pub fn verify_range_proof(&self, stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
        self.verify_range_proof_inner(stmt, proof, None)
    }

    // statement (msg_g, g, ciphertext, ek), witness (msg, randomness)
    //   such that ciphertext = Enc(ek, msg, randomness) and -q^3 < msg < q^3
    //   and msg_g = msg * g (this is the additional "check")
    // adapted from appendix A.1 of https://eprint.iacr.org/2019/114.pdf
    // full specification: section 4.4, proof \Pi_i of https://eprint.iacr.org/2016/013.pdf
    pub fn range_proof_wc(&self, stmt: &StatementWc, wit: &Witness) -> ProofWc {
        let (proof, u1) = self.range_proof_inner(&stmt.stmt, Some((stmt.msg_g, stmt.g)), wit);
        ProofWc {
            proof,
            u1: u1.unwrap(),
        }
    }

    pub fn verify_range_proof_wc(
        &self,
        stmt: &StatementWc,
        proof: &ProofWc,
    ) -> Result<(), &'static str> {
        self.verify_range_proof_inner(
            &stmt.stmt,
            &proof.proof,
            Some((stmt.msg_g, stmt.g, &proof.u1)),
        )
    }

    #[allow(clippy::many_single_char_names)]
    fn range_proof_inner(
        &self,
        stmt: &Statement,
        msg_g_g: Option<(&GE, &GE)>, // (msg_g, g)
        wit: &Witness,
    ) -> (Proof, Option<GE>) {
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

        let u1 = msg_g_g.map::<GE, _>(|(_, g)| {
            let alpha: FE = ECScalar::from(&alpha);
            g * &alpha
        });

        let e = HSha256::create_hash(&[
            &stmt.ek.n,
            // TODO add stmt.ek.gamma to this hash like binance? zengo puts a bunch of other crap in here
            &stmt.ciphertext,
            &msg_g_g.map_or(BigInt::zero(), |(msg_g, _)| {
                msg_g.bytes_compressed_to_big_int()
            }),
            &msg_g_g.map_or(BigInt::zero(), |(_, g)| g.bytes_compressed_to_big_int()),
            &z,
            &u,
            &u1.map_or(BigInt::zero(), |u1| u1.bytes_compressed_to_big_int()),
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

        (Proof { z, u, w, s, s1, s2 }, u1)
    }

    fn verify_range_proof_inner(
        &self,
        stmt: &Statement,
        proof: &Proof,
        msg_g_g_u1: Option<(&GE, &GE, &GE)>, // (msg_g, g, u1)
    ) -> Result<(), &'static str> {
        if proof.s1 > self.public.q3 || proof.s1 < BigInt::zero() {
            return Err("s1 not in range q^3");
        }
        let e_neg = HSha256::create_hash(&[
            &stmt.ek.n,
            &stmt.ciphertext,
            &msg_g_g_u1.map_or(BigInt::zero(), |(msg_g, _, _)| {
                msg_g.bytes_compressed_to_big_int()
            }),
            &msg_g_g_u1.map_or(BigInt::zero(), |(_, g, _)| g.bytes_compressed_to_big_int()),
            &proof.z,
            &proof.u,
            &msg_g_g_u1.map_or(BigInt::zero(), |(_, _, u1)| {
                u1.bytes_compressed_to_big_int()
            }),
            &proof.w,
        ])
        .modulus(&FE::q())
        .neg();

        if let Some((msg_g, g, u1)) = msg_g_g_u1 {
            let s1: FE = ECScalar::from(&proof.s1);
            let s1_g = g * &s1;
            let e_neg: FE = ECScalar::from(&e_neg);
            let u1_check = msg_g * &e_neg + s1_g;
            if u1_check != *u1 {
                return Err("'wc' check fail");
            }
        }

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
            return Err("u check fail");
        }

        let w_check = BigInt::mod_mul(
            &self.public.commit(&proof.s1, &proof.s2),
            &BigInt::mod_pow(&proof.z, &e_neg, &self.public.n_tilde),
            &self.public.n_tilde,
        );
        if w_check != proof.w {
            return Err("w check fail");
        }

        Ok(())
    }
}

pub fn corrupt_proof(proof: &Proof) -> Proof {
    let proof = proof.clone();
    Proof {
        u: proof.u + BigInt::from(1),
        ..proof
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        Zkp, {Proof, ProofWc, Statement, StatementWc, Witness},
    };
    use curv::{
        elliptic::curves::traits::{ECPoint, ECScalar},
        BigInt, FE, GE,
    };
    use paillier::{
        EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext,
    };

    #[test]
    fn basic_correctness() {
        // create a (statement, witness) pair
        let (ek, _dk) = &Paillier::keypair().keys(); // not using safe primes
        let msg = &FE::new_random();
        let g = &GE::generator();
        let msg_g = &(g * msg);
        let randomness = Randomness::sample(&ek);
        let ciphertext = &Paillier::encrypt_with_chosen_randomness(
            ek,
            RawPlaintext::from(msg.to_big_int()),
            &randomness,
        )
        .0
        .clone()
        .into_owned();

        let stmt_wc = &StatementWc {
            stmt: Statement { ciphertext, ek },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness {
            msg,
            randomness: &randomness.0,
        };
        let zkp = Zkp::new_unsafe();

        // test: valid proof
        let proof = zkp.range_proof(stmt, wit);
        zkp.verify_range_proof(stmt, &proof).unwrap();

        // test: valid proof wc (with check)
        let proof_wc = zkp.range_proof_wc(stmt_wc, wit);
        zkp.verify_range_proof_wc(stmt_wc, &proof_wc).unwrap();

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        zkp.verify_range_proof_wc(stmt_wc, &bad_proof_wc)
            .unwrap_err();

        // test: bad witness
        let one: FE = ECScalar::from(&BigInt::from(1));
        let bad_wit = &Witness {
            msg: &(*wit.msg + one),
            ..*wit
        };
        let bad_proof = zkp.range_proof(stmt, bad_wit);
        zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = zkp.range_proof_wc(stmt_wc, bad_wit);
        zkp.verify_range_proof_wc(stmt_wc, &bad_wit_proof_wc)
            .unwrap_err();
    }

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        let proof = proof.clone();
        Proof {
            u: proof.u + BigInt::from(1),
            ..proof
        }
    }
    pub fn corrupt_proof_wc(proof_wc: &ProofWc) -> ProofWc {
        let proof_wc = proof_wc.clone();
        ProofWc {
            proof: Proof {
                w: proof_wc.proof.w + BigInt::from(1),
                ..proof_wc.proof
            },
            ..proof_wc
        }
    }
    // curv library sucks so bad that I cannot possibly write a corrupt_witness function
    // curv library does not allow in-place arithmetic, which I need to act on
}
