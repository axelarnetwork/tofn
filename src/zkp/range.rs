use std::ops::Neg;

use crate::zkp::Zkp;
use curv::{
    arithmetic::traits::{Modulo, Samplable},
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::ECScalar,
    BigInt, FE,
};
use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};

pub struct Statement<'a> {
    pub ciphertext: &'a BigInt,
    pub ek: &'a EncryptionKey,
}
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

impl Zkp {
    // statement (ciphertext, ek), witness (msg, randomness)
    //   such that ciphertext = Enc(ek, msg, randomness) and -q^3 < msg < q^3
    // See appendix A.1 of https://eprint.iacr.org/2019/114.pdf
    // Used by Alice in the first message of MtA
    #[allow(clippy::many_single_char_names)]
    pub fn range_proof(&self, stmt: &Statement, wit: &Witness) -> Proof {
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

        Proof { z, u, w, s, s1, s2 }
    }

    pub fn verify_range_proof(&self, stmt: &Statement, proof: &Proof) -> Result<(), ()> {
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

#[cfg(test)]
mod tests {
    use super::{
        Zkp, {Proof, Statement, Witness},
    };
    use curv::{
        // arithmetic::traits::{Modulo, Samplable},
        // cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
        elliptic::curves::traits::ECScalar,
        BigInt,
        FE,
    };
    use paillier::{
        EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext,
    };

    #[test]
    fn basic_correctness() {
        let (ek, _dk) = Paillier::keypair().keys(); // not using safe primes
        let msg = &FE::new_random();
        let randomness = Randomness::sample(&ek);
        let ciphertext = &Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(msg.to_big_int()),
            &randomness,
        )
        .0
        .clone()
        .into_owned();

        let stmt = Statement {
            ciphertext,
            ek: &ek,
        };
        let wit = Witness {
            msg,
            randomness: &randomness.0,
        };
        let zkp = Zkp::new_unsafe();

        // test: valid proof
        let proof = zkp.range_proof(&stmt, &wit);
        zkp.verify_range_proof(&stmt, &proof).unwrap();

        // test: bad proof
        let bad_proof = Proof {
            u: proof.u + BigInt::from(1),
            ..proof
        };
        zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();

        // test: bad witness
        let one: FE = ECScalar::from(&BigInt::from(1));
        let bad_wit = Witness {
            msg: &(*wit.msg + one),
            ..wit
        };
        let bad_proof = zkp.range_proof(&stmt, &bad_wit);
        zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();
    }
}
