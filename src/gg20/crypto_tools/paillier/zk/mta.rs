use crate::{
    gg20::{
        constants,
        crypto_tools::{
            k256_serde,
            paillier::{
                to_bigint, to_scalar, to_vec,
                zk::{mulm, random, ZkSetup},
                BigInt, Ciphertext, EncryptionKey, Plaintext, Randomness,
            },
        },
    },
    sdk::api::{TofnFatal, TofnResult},
};
use ecdsa::hazmat::FromDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use super::secp256k1_modulus_cubed;

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub ciphertext1: &'a Ciphertext,
    pub ciphertext2: &'a Ciphertext,
    pub ek: &'a EncryptionKey,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub x: &'a k256::Scalar,
    pub msg: &'a Plaintext,
    pub randomness: &'a Randomness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    z: BigInt,
    z_prime: BigInt,
    t: BigInt,
    v: BigInt,
    w: BigInt,
    s: Randomness,
    s1: BigInt,
    s2: BigInt,
    t1: Plaintext,
    t2: BigInt,
}

#[derive(Clone, Debug)]
pub struct StatementWc<'a> {
    pub stmt: Statement<'a>,
    pub x_g: &'a k256::ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWc {
    proof: Proof,
    u: k256_serde::ProjectivePoint,
}

impl ZkSetup {
    // statement (ciphertext1, ciphertext2, ek), witness (x, msg, randomness)
    //   such that ciphertext2 = x *' ciphertext1 +' Enc(ek, msg, randomness) and -q^3 < x < q^3
    //   where *' and +' denote homomorphic operations on ciphertexts
    // notation follows appendix A.3 of https://eprint.iacr.org/2019/114.pdf
    // used by Bob (the "respondent") in MtA protocol
    // MtA : Multiplicative to Additive
    pub fn mta_proof(&self, stmt: &Statement, wit: &Witness) -> Proof {
        self.mta_proof_inner(constants::MTA_PROOF_TAG, stmt, None, wit)
            .0
    }

    pub fn verify_mta_proof(&self, stmt: &Statement, proof: &Proof) -> bool {
        self.verify_mta_proof_inner(constants::MTA_PROOF_TAG, stmt, proof, None)
    }

    // statement (ciphertext1, ciphertext2, ek, x_g), witness (x, msg, randomness)
    //   such that ciphertext2 = x *' ciphertext1 +' Enc(ek, msg, randomness) and -q^3 < x < q^3
    //   and x_g = x * G (this is the additional "check")
    //   where *' and +' denote homomorphic operations on ciphertexts
    // notation follows appendix A.2 of https://eprint.iacr.org/2019/114.pdf
    // used by Bob (the "respondent") in MtAwc protocol
    // MtAwc : Multiplicative to Additive with check
    pub fn mta_proof_wc(&self, stmt: &StatementWc, wit: &Witness) -> TofnResult<ProofWc> {
        let (proof, u) =
            self.mta_proof_inner(constants::MTA_PROOF_WC_TAG, &stmt.stmt, Some(stmt.x_g), wit);

        let u = u
            .ok_or_else(|| {
                error!("mta proof wc: missing u");
                TofnFatal
            })?
            .into();

        Ok(ProofWc { proof, u })
    }

    pub fn verify_mta_proof_wc(&self, stmt: &StatementWc, proof: &ProofWc) -> bool {
        self.verify_mta_proof_inner(
            constants::MTA_PROOF_WC_TAG,
            &stmt.stmt,
            &proof.proof,
            Some((stmt.x_g, proof.u.as_ref())),
        )
    }

    #[allow(clippy::many_single_char_names)]
    fn mta_proof_inner(
        &self,
        tag: u8,
        stmt: &Statement,
        x_g: Option<&k256::ProjectivePoint>,
        wit: &Witness,
    ) -> (Proof, Option<k256::ProjectivePoint>) {
        let alpha = random(&secp256k1_modulus_cubed());

        let sigma = random(&self.q_n_tilde);
        let tau = random(&self.q_n_tilde);
        let rho = random(&self.q_n_tilde);

        let rho_prime = random(&self.q3_n_tilde);

        let beta = stmt.ek.sample_randomness();
        let gamma = Plaintext(stmt.ek.sample_randomness().0.clone());

        let x_bigint = to_bigint(wit.x);

        let z = self.commit(&x_bigint, &rho);
        let z_prime = self.commit(&alpha, &rho_prime);
        let t = self.commit(&wit.msg.0, &sigma);

        let u = x_g.map::<k256::ProjectivePoint, _>(|_| {
            k256::ProjectivePoint::generator() * to_scalar(&alpha)
        });

        let v = mulm(
            &stmt.ek.encrypt_with_randomness(&gamma, &beta).0,
            &stmt.ciphertext1.0.powm(&alpha, &stmt.ek.0.nn),
            &stmt.ek.0.nn,
        );

        let w = self.commit(&gamma.0, &tau);

        let e = to_bigint(&k256::Scalar::from_digest(
            Sha256::new()
                .chain(tag.to_le_bytes())
                .chain(to_vec(&stmt.ek.0.n))
                .chain(to_vec(&stmt.ciphertext1.0))
                .chain(to_vec(&stmt.ciphertext2.0))
                .chain(x_g.map_or(Vec::new(), |x_g| k256_serde::to_bytes(x_g)))
                .chain(to_vec(&z))
                .chain(to_vec(&z_prime))
                .chain(to_vec(&t))
                .chain(&u.map_or(Vec::new(), |u| k256_serde::to_bytes(&u)))
                .chain(to_vec(&v))
                .chain(to_vec(&w)),
        ));

        let s = Randomness(mulm(
            &wit.randomness.0.powm(&e, &stmt.ek.0.n),
            &beta.0,
            &stmt.ek.0.n,
        ));
        let s1 = &e * &x_bigint + alpha;
        let s2 = &e * rho + rho_prime;
        let t1 = Plaintext(&e * &wit.msg.0 + gamma.0.clone());
        let t2 = e * sigma + tau;

        (
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
            },
            u,
        )
    }

    fn verify_mta_proof_inner(
        &self,
        tag: u8,
        stmt: &Statement,
        proof: &Proof,
        x_g_u: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (x_g, u)
    ) -> bool {
        if proof.s1 > secp256k1_modulus_cubed() || proof.s1 < BigInt::zero() {
            warn!("s1 not in range q^3");
            return false;
        }

        let e = k256::Scalar::from_digest(
            Sha256::new()
                .chain(tag.to_le_bytes())
                .chain(to_vec(&stmt.ek.0.n))
                .chain(to_vec(&stmt.ciphertext1.0))
                .chain(to_vec(&stmt.ciphertext2.0))
                .chain(x_g_u.map_or(Vec::new(), |(x_g, _)| k256_serde::to_bytes(x_g)))
                .chain(to_vec(&proof.z))
                .chain(to_vec(&proof.z_prime))
                .chain(to_vec(&proof.t))
                .chain(x_g_u.map_or(Vec::new(), |(_, u)| k256_serde::to_bytes(u)))
                .chain(to_vec(&proof.v))
                .chain(to_vec(&proof.w)),
        );
        let e_bigint = to_bigint(&e);

        if let Some((x_g, u)) = x_g_u {
            let s1 = to_scalar(&proof.s1);
            let s1_g = k256::ProjectivePoint::generator() * s1;
            let s1_g_check = x_g * &e + u;
            if s1_g_check != s1_g {
                warn!("'wc' check fail");
                return false;
            }
        }

        let z_e_z_prime = mulm(
            &proof.z.powm(&e_bigint, self.n_tilde()),
            &proof.z_prime,
            self.n_tilde(),
        );
        let z_e_z_prime_check = self.commit(&proof.s1, &proof.s2);
        if z_e_z_prime_check != z_e_z_prime {
            warn!("z^e z_prime check fail");
            return false;
        }

        let t_e_w = mulm(
            &proof.t.powm(&e_bigint, self.n_tilde()),
            &proof.w,
            self.n_tilde(),
        );
        let t_e_w_check = self.commit(&proof.t1.0, &proof.t2);
        if t_e_w_check != t_e_w {
            warn!("t^e w check fail");
            return false;
        }

        let cipher_check_lhs = mulm(
            &stmt.ek.encrypt_with_randomness(&proof.t1, &proof.s).0,
            &stmt.ciphertext1.0.powm(&proof.s1, &stmt.ek.0.nn),
            &stmt.ek.0.nn,
        );
        let cipher_check_rhs = mulm(
            &proof.v,
            &stmt.ciphertext2.0.powm(&e_bigint, &stmt.ek.0.nn),
            &stmt.ek.0.nn,
        );
        if cipher_check_lhs != cipher_check_rhs {
            warn!("cipher check fail");
            return false;
        }

        true
    }
}

// in contrast with the rest of malicious modules in tofn, we include the
// malicious module of
// 1. zkp::mta
// 2. zkp::pedersen
// 3. zkp::range
// in non-malicious test build to avoid code-duplication for malicious tests.
#[cfg(any(test, feature = "malicious"))]
pub mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        let proof = proof.clone();
        Proof {
            v: proof.v + BigInt::from(1),
            ..proof
        }
    }

    pub fn corrupt_proof_wc(proof: &ProofWc) -> ProofWc {
        let proof = proof.clone();
        ProofWc {
            u: k256_serde::ProjectivePoint::from(
                k256::ProjectivePoint::generator() + proof.u.as_ref(),
            ),
            ..proof
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        malicious::{corrupt_proof, corrupt_proof_wc},
        BigInt, Statement, StatementWc, Witness, ZkSetup,
    };
    use crate::gg20::crypto_tools::paillier::{keygen_unsafe, zk::random, Ciphertext, Plaintext};
    use ecdsa::elliptic_curve::Field;
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn basic_correctness() {
        // create a (statement, witness) pair
        let (ek, _dk) = &keygen_unsafe(&mut rand::thread_rng());
        let msg = &Plaintext(ek.sample_randomness().0.clone());
        let x = &k256::Scalar::random(rand::thread_rng());
        let x_g = &(k256::ProjectivePoint::generator() * x);
        let randomness = &ek.sample_randomness();
        let ciphertext1 = &Ciphertext(random(&ek.0.nn));
        let ciphertext2 = &ek.add(
            &ek.mul(ciphertext1, &Plaintext::from_scalar(x)),
            &ek.encrypt_with_randomness(msg, randomness),
        );

        let stmt_wc = &StatementWc {
            stmt: Statement {
                ciphertext1,
                ciphertext2,
                ek,
            },
            x_g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { x, msg, randomness };
        let (zkp, _) = ZkSetup::new_unsafe(&mut rand::thread_rng());

        // test: valid proof
        let proof = zkp.mta_proof(stmt, wit);
        assert!(zkp.verify_mta_proof(stmt, &proof));

        // test: valid proof wc (with check)
        let proof_wc = zkp.mta_proof_wc(stmt_wc, wit).unwrap();
        assert!(zkp.verify_mta_proof_wc(stmt_wc, &proof_wc));

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        assert!(!zkp.verify_mta_proof(stmt, &bad_proof));

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        assert!(!zkp.verify_mta_proof_wc(stmt_wc, &bad_proof_wc));

        // test: bad witness
        let bad_wit = &Witness {
            msg: &Plaintext(&wit.msg.0 + BigInt::one()),
            ..*wit
        };
        let bad_wit_proof = zkp.mta_proof(stmt, bad_wit);
        assert!(!zkp.verify_mta_proof(stmt, &bad_wit_proof));

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = zkp.mta_proof_wc(stmt_wc, bad_wit).unwrap();
        assert!(!zkp.verify_mta_proof_wc(stmt_wc, &bad_wit_proof_wc));
    }
}
