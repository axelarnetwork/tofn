use std::ops::Neg;

use crate::{
    k256_serde,
    paillier_k256::{
        to_bigint, to_scalar, to_vec,
        zk::{random, ZkSetup},
        BigInt, Ciphertext, EncryptionKey, Plaintext, Randomness,
    },
};
use ecdsa::hazmat::FromDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::mulm;

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub ciphertext: &'a Ciphertext,
    pub ek: &'a EncryptionKey,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub msg: &'a k256::Scalar,
    pub randomness: &'a Randomness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    z: BigInt,
    u: Ciphertext,
    w: BigInt,
    s: Randomness,
    s1: Plaintext,
    s2: BigInt,
}

#[derive(Clone, Debug)]
pub struct StatementWc<'a> {
    pub stmt: Statement<'a>,
    pub msg_g: &'a k256::ProjectivePoint,
    pub g: &'a k256::ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWc {
    proof: Proof,
    u1: k256_serde::ProjectivePoint,
}

impl ZkSetup {
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
            u1: k256_serde::ProjectivePoint::from(u1.unwrap()),
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
            Some((stmt.msg_g, stmt.g, &proof.u1.unwrap())),
        )
    }

    #[allow(clippy::many_single_char_names)]
    fn range_proof_inner(
        &self,
        stmt: &Statement,
        msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (msg_g, g)
        wit: &Witness,
    ) -> (Proof, Option<k256::ProjectivePoint>) {
        let alpha_pt = Plaintext(random(&self.q3));
        let alpha_bigint = &alpha_pt.0;
        let rho = random(&self.q_n_tilde);
        let gamma = random(&self.q3_n_tilde);

        let z = self.commit(&to_bigint(&wit.msg), &rho);
        let (u, beta) = stmt.ek.encrypt(&alpha_pt);
        let w = self.commit(&alpha_bigint, &gamma);

        let u1 = msg_g_g.map::<k256::ProjectivePoint, _>(|(_, g)| g * &alpha_pt.to_scalar());

        let e = k256::Scalar::from_digest(
            Sha256::new()
                .chain(to_vec(&stmt.ek.0.n))
                .chain(to_vec(&stmt.ciphertext.0))
                .chain(&msg_g_g.map_or(Vec::new(), |(msg_g, _)| k256_serde::to_bytes(&msg_g)))
                .chain(&msg_g_g.map_or(Vec::new(), |(_, g)| k256_serde::to_bytes(&g)))
                .chain(to_vec(&z))
                .chain(to_vec(&u.0))
                .chain(&u1.map_or(Vec::new(), |u1| k256_serde::to_bytes(&u1)))
                .chain(to_vec(&w)),
        );
        let e_bigint = to_bigint(&e);

        let s = Randomness(mulm(
            &wit.randomness.0.powm(&e_bigint, &stmt.ek.0.n),
            &beta.0,
            &stmt.ek.0.n,
        ));
        let s1 = Plaintext(e_bigint.clone() * to_bigint(wit.msg) + alpha_bigint);
        let s2 = e_bigint * rho + gamma;

        (Proof { z, u, w, s, s1, s2 }, u1)
    }

    fn verify_range_proof_inner(
        &self,
        stmt: &Statement,
        proof: &Proof,
        msg_g_g_u1: Option<(
            &k256::ProjectivePoint,
            &k256::ProjectivePoint,
            &k256::ProjectivePoint,
        )>, // (msg_g, g, u1)
    ) -> Result<(), &'static str> {
        if proof.s1.0 > self.q3 || proof.s1.0 < BigInt::zero() {
            return Err("s1 not in range q^3");
        }
        let e = k256::Scalar::from_digest(
            Sha256::new()
                .chain(to_vec(&stmt.ek.0.n))
                .chain(to_vec(&stmt.ciphertext.0))
                .chain(&msg_g_g_u1.map_or(Vec::new(), |(msg_g, _, _)| k256_serde::to_bytes(&msg_g)))
                .chain(&msg_g_g_u1.map_or(Vec::new(), |(_, g, _)| k256_serde::to_bytes(&g)))
                .chain(to_vec(&proof.z))
                .chain(to_vec(&proof.u.0))
                .chain(&msg_g_g_u1.map_or(Vec::new(), |(_, _, u1)| k256_serde::to_bytes(&u1)))
                .chain(to_vec(&proof.w)),
        );
        let e_neg_bigint = to_bigint(&e).neg();
        let e_neg = e.negate();

        if let Some((msg_g, g, u1)) = msg_g_g_u1 {
            let s1 = to_scalar(&proof.s1.0);
            let s1_g = g * &s1;
            let u1_check = msg_g * &e_neg + s1_g;
            if u1_check != *u1 {
                return Err("'wc' check fail");
            }
        }

        let u_check = mulm(
            &stmt.ek.encrypt_with_randomness(&proof.s1, &proof.s).0,
            &stmt.ciphertext.0.powm(&e_neg_bigint, &stmt.ek.0.nn),
            &stmt.ek.0.nn,
        );
        if u_check != proof.u.0 {
            return Err("u check fail");
        }

        let w_check = mulm(
            &self.commit(&proof.s1.0, &proof.s2),
            &proof.z.powm(&e_neg_bigint, self.n_tilde()),
            self.n_tilde(),
        );
        if w_check != proof.w {
            return Err("w check fail");
        }

        Ok(())
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
    use crate::k256_serde::ProjectivePoint;

    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        let proof = proof.clone();
        Proof {
            u: Ciphertext(proof.u.0 + BigInt::one()),
            ..proof
        }
    }

    pub fn corrupt_proof_wc(proof_wc: &ProofWc) -> ProofWc {
        let proof_wc = proof_wc.clone();
        ProofWc {
            u1: ProjectivePoint::from(k256::ProjectivePoint::generator() + proof_wc.u1.unwrap()),
            ..proof_wc
        }
    }
}
#[cfg(test)]
pub mod tests {
    use crate::paillier_k256::keygen_unsafe;

    use super::{
        ZkSetup,
        {
            malicious::{corrupt_proof, corrupt_proof_wc},
            Statement, StatementWc, Witness,
        },
    };
    use ecdsa::elliptic_curve::Field;
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn basic_correctness() {
        // create a (statement, witness) pair
        let (ek, _dk) = &keygen_unsafe();
        let msg = &k256::Scalar::random(rand::thread_rng());
        let g = &k256::ProjectivePoint::generator();
        let msg_g = &(g * msg);
        let (ciphertext, randomness) = &ek.encrypt(&msg.into());

        let stmt_wc = &StatementWc {
            stmt: Statement { ciphertext, ek },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { msg, randomness };
        let zkp = ZkSetup::new_unsafe();

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
        let bad_wit = &Witness {
            msg: &(*wit.msg + k256::Scalar::one()),
            ..*wit
        };
        let bad_proof = zkp.range_proof(stmt, bad_wit);
        zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();
        let bad_wit_proof_wc = zkp.range_proof_wc(stmt_wc, bad_wit);
        zkp.verify_range_proof_wc(stmt_wc, &bad_wit_proof_wc)
            .unwrap_err();
    }
}
