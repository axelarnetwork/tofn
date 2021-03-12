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
    pub ciphertext1: &'a BigInt,
    pub ciphertext2: &'a BigInt,
    pub ek: &'a EncryptionKey,
}
pub struct Witness<'a> {
    pub x: &'a FE,
    pub msg: &'a BigInt,
    pub randomness: &'a BigInt, // TODO use Paillier::Ransomness instead?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    z: BigInt,
    z_prime: BigInt,
    t: BigInt,
    v: BigInt,
    w: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
    t1: BigInt,
    t2: BigInt,
}

impl Zkp {
    // statement (ciphertext1, ciphertext2, ek), witness (x, msg, randomness)
    //   such that ciphertext2 = x *' ciphertext1 +' Enc(ek, msg, randomness) and -q^3 < x < q^3
    //   where *' and +' denote homomorphic operations on ciphertexts
    // notation follows appendix A.3 of https://eprint.iacr.org/2019/114.pdf
    // used by Bob (the "respondent") in MtA protocol
    #[allow(clippy::many_single_char_names)]
    pub fn mta_resp_proof(&self, stmt: &Statement, wit: &Witness) -> Proof {
        let alpha = BigInt::sample_below(&self.public.q3);

        let sigma = BigInt::sample_below(&self.public.q_n_tilde);
        let tau = BigInt::sample_below(&self.public.q_n_tilde);
        let rho = BigInt::sample_below(&self.public.q_n_tilde);

        let rho_prime = BigInt::sample_below(&self.public.q3_n_tilde);

        let beta = Randomness::sample(&stmt.ek); // TODO sample() may not be coprime to stmt.ek.n; do we care?
        let gamma = Randomness::sample(&stmt.ek).0; // TODO sample() may not be coprime to stmt.ek.n; do we care?

        let z = self.public.commit(&wit.x.to_big_int(), &rho);
        let z_prime = self.public.commit(&alpha, &rho_prime);
        let t = self.public.commit(&wit.msg, &sigma);

        let v = BigInt::mod_mul(
            &Paillier::encrypt_with_chosen_randomness(stmt.ek, RawPlaintext::from(&gamma), &beta).0,
            &BigInt::mod_pow(&stmt.ciphertext1, &alpha, &stmt.ek.nn),
            &stmt.ek.nn,
        );

        let w = self.public.commit(&gamma, &tau);

        let e = HSha256::create_hash(&[
            &stmt.ek.n,
            // TODO add stmt.ek.gamma to this hash like binance? zengo puts a bunch of other crap in here
            &stmt.ciphertext1,
            &stmt.ciphertext2,
            &z,
            &z_prime,
            &t,
            &v,
            &w,
        ])
        .modulus(&FE::q());

        let s = BigInt::mod_mul(
            &BigInt::mod_pow(&wit.randomness, &e, &stmt.ek.n),
            &beta.0,
            &stmt.ek.n,
        );
        let s1 = &e * wit.x.to_big_int() + alpha;
        let s2 = &e * rho + rho_prime;
        let t1 = &e * wit.msg + gamma;
        let t2 = e * sigma + tau;

        Proof {
            z,
            z_prime,
            t,
            v,
            w,
            s,
            s1,
            s2,
            t1,
            t2,
        }
    }

    pub fn verify_mta_resp_proof(
        &self,
        stmt: &Statement,
        proof: &Proof,
    ) -> Result<(), &'static str> {
        if proof.s1 > self.public.q3 || proof.s1 < BigInt::zero() {
            return Err("s1 not in range q^3");
        }
        let e = HSha256::create_hash(&[
            &stmt.ek.n,
            &stmt.ciphertext1,
            &stmt.ciphertext2,
            &proof.z,
            &proof.z_prime,
            &proof.t,
            &proof.v,
            &proof.w,
        ])
        .modulus(&FE::q());

        let z_e_z_prime = BigInt::mod_mul(
            &BigInt::mod_pow(&proof.z, &e, &self.public.n_tilde),
            &proof.z_prime,
            &self.public.n_tilde,
        );
        let z_e_z_prime_check = self.public.commit(&proof.s1, &proof.s2);
        if z_e_z_prime_check != z_e_z_prime {
            return Err("z^e z_prime check fail");
        }

        let t_e_w = BigInt::mod_mul(
            &BigInt::mod_pow(&proof.t, &e, &self.public.n_tilde),
            &proof.w,
            &self.public.n_tilde,
        );
        let t_e_w_check = self.public.commit(&proof.t1, &proof.t2);
        if t_e_w_check != t_e_w {
            return Err("t^e w check fail");
        }

        let chipher_check_lhs = BigInt::mod_mul(
            &Paillier::encrypt_with_chosen_randomness(
                stmt.ek,
                RawPlaintext::from(&proof.t1),
                &Randomness::from(&proof.s),
            )
            .0,
            &BigInt::mod_pow(&stmt.ciphertext1, &proof.s1, &stmt.ek.nn),
            &stmt.ek.nn,
        );
        let chipher_check_rhs = BigInt::mod_mul(
            &proof.v,
            &BigInt::mod_pow(&stmt.ciphertext2, &e, &stmt.ek.nn),
            &stmt.ek.nn,
        );
        if chipher_check_lhs != chipher_check_rhs {
            return Err("chipher check fail");
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
        arithmetic::traits::Samplable,
        // cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
        elliptic::curves::traits::ECScalar,
        BigInt,
        FE,
    };
    use paillier::{
        Add, EncryptWithChosenRandomness, KeyGeneration, Mul, Paillier, Randomness, RawCiphertext,
        RawPlaintext,
    };

    #[test]
    fn basic_correctness() {
        // create a (statement, witness) pair:
        // statement (ciphertext1, ciphertext2, ek), witness (x, msg, randomness)
        //   such that ciphertext2 = x *' ciphertext1 +' Enc(ek, msg, randomness) and -q^3 < x < q^3
        let (ek, _dk) = &Paillier::keypair().keys(); // not using safe primes
        let msg = &BigInt::sample_below(&ek.n);
        let x = &FE::new_random();
        let randomness = &Randomness::sample(&ek);
        let ciphertext1 = &BigInt::sample_below(&ek.nn);
        let ciphertext2 = &Paillier::add(
            ek,
            Paillier::mul(
                ek,
                RawCiphertext::from(ciphertext1),
                RawPlaintext::from(x.to_big_int()),
            ),
            Paillier::encrypt_with_chosen_randomness(ek, RawPlaintext::from(msg), randomness),
        )
        .0;

        let stmt = Statement {
            ciphertext1,
            ciphertext2,
            ek,
        };
        let wit = Witness {
            msg,
            randomness: &randomness.0,
            x,
        };
        let zkp = Zkp::new_unsafe();

        // test: valid proof
        let proof = zkp.mta_resp_proof(&stmt, &wit);
        zkp.verify_mta_resp_proof(&stmt, &proof).unwrap();

        // test: bad proof
        let bad_proof = Proof {
            v: proof.v + BigInt::from(1),
            ..proof
        };
        zkp.verify_mta_resp_proof(&stmt, &bad_proof).unwrap_err();

        // test: bad witness
        let bad_wit = Witness {
            msg: &(wit.msg + BigInt::from(1)),
            ..wit
        };
        let bad_wit_proof = zkp.mta_resp_proof(&stmt, &bad_wit);
        zkp.verify_mta_resp_proof(&stmt, &bad_wit_proof)
            .unwrap_err();
    }
}
