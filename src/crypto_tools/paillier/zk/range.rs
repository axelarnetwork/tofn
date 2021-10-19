use std::ops::Neg;

use crate::{
    collections::TypedUsize,
    crypto_tools::{
        constants, k256_serde,
        paillier::{
            secp256k1_modulus, to_bigint, to_scalar,
            utils::{member_of_mod, member_of_mul_group},
            zk::ZkSetup,
            Ciphertext, EncryptionKey, Plaintext, Randomness,
        },
    },
    gg20::sign::SignShareId,
    sdk::api::{TofnFatal, TofnResult},
};
use ecdsa::hazmat::FromDigest;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use super::secp256k1_modulus_cubed;

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub prover_id: TypedUsize<SignShareId>,
    pub verifier_id: TypedUsize<SignShareId>,
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
    z: BigNumber,
    u: Ciphertext,
    w: BigNumber,
    s: Randomness,
    s1: Plaintext,
    s2: Randomness,
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
        self.range_proof_inner(constants::RANGE_PROOF_TAG, stmt, None, wit)
            .0
    }

    pub fn verify_range_proof(&self, stmt: &Statement, proof: &Proof) -> bool {
        self.verify_range_proof_inner(constants::RANGE_PROOF_TAG, stmt, proof, None)
    }

    // statement (msg_g, g, ciphertext, ek), witness (msg, randomness)
    //   such that ciphertext = Enc(ek, msg, randomness) and -q^3 < msg < q^3
    //   and msg_g = msg * g (this is the additional "check")
    // adapted from appendix A.1 of https://eprint.iacr.org/2019/114.pdf
    // full specification: section 4.4, proof \Pi_i of https://eprint.iacr.org/2016/013.pdf
    pub fn range_proof_wc(&self, stmt: &StatementWc, wit: &Witness) -> TofnResult<ProofWc> {
        let (proof, u1) = self.range_proof_inner(
            constants::RANGE_PROOF_WC_TAG,
            &stmt.stmt,
            Some((stmt.msg_g, stmt.g)),
            wit,
        );

        let u1 = u1
            .ok_or_else(|| {
                error!("range proof wc: missing u1");
                TofnFatal
            })?
            .into();

        Ok(ProofWc { proof, u1 })
    }

    pub fn verify_range_proof_wc(&self, stmt: &StatementWc, proof: &ProofWc) -> bool {
        self.verify_range_proof_inner(
            constants::RANGE_PROOF_WC_TAG,
            &stmt.stmt,
            &proof.proof,
            Some((stmt.msg_g, stmt.g, proof.u1.as_ref())),
        )
    }

    /// Compute the challenge e in Z_q for the range proof
    fn compute_range_proof_challenge(
        tag: u8,
        stmt: &Statement,
        msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (msg_g, g)
        z: &BigNumber,
        u: &Ciphertext,
        u1: Option<&k256::ProjectivePoint>,
        w: &BigNumber,
    ) -> k256::Scalar {
        let e = k256::Scalar::from_digest(
            Sha256::new()
                .chain(tag.to_be_bytes())
                .chain(stmt.prover_id.to_bytes())
                .chain(stmt.verifier_id.to_bytes())
                .chain(stmt.ek.0.n().to_bytes())
                .chain(stmt.ciphertext.0.to_bytes())
                .chain(msg_g_g.map_or([0; 33], |(msg_g, _)| k256_serde::point_to_bytes(msg_g)))
                .chain(msg_g_g.map_or([0; 33], |(_, g)| k256_serde::point_to_bytes(g)))
                .chain(z.to_bytes())
                .chain(u.0.to_bytes())
                .chain(u1.map_or([0; 33], |u1| k256_serde::point_to_bytes(u1)))
                .chain(w.to_bytes()),
        );

        e
    }

    #[allow(clippy::many_single_char_names)]
    fn range_proof_inner(
        &self,
        tag: u8,
        stmt: &Statement,
        msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (msg_g, g)
        wit: &Witness,
    ) -> (Proof, Option<k256::ProjectivePoint>) {
        // Assume: m in Z_q
        debug_assert!(member_of_mod(&to_bigint(wit.msg), &secp256k1_modulus()));

        // Assume: r in Z*_N
        debug_assert!(member_of_mul_group(&wit.randomness.0, stmt.ek.0.n()));

        // Assume: c in Z*_N^2
        debug_assert!(member_of_mul_group(&stmt.ciphertext.0, stmt.ek.0.nn()));

        // Sample alpha from Z_q^3
        let alpha = Plaintext::generate(&secp256k1_modulus_cubed());

        let q_n_tilde = secp256k1_modulus() * self.n_tilde();
        let q3_n_tilde = secp256k1_modulus_cubed() * self.n_tilde();

        // Sample rho from Z_(q N~)
        let rho = Randomness::generate(&q_n_tilde);
        // Sample gamma from Z_(q^3 N~)
        let gamma = Randomness::generate(&q3_n_tilde);

        let msg_bigint = Plaintext(to_bigint(wit.msg));

        // z = h1^m h2^rho mod N~
        let z = self.commit(&msg_bigint, &rho);

        // Sample beta from Z*_N
        // u = Paillier-Enc(alpha, beta)
        let (u, beta) = stmt.ek.encrypt(&alpha);

        // w = h1^alpha h2^gamma mod N~
        let w = self.commit(&alpha, &gamma);

        // u1 = g^alpha
        let u1 = msg_g_g.map::<k256::ProjectivePoint, _>(|(_, g)| g * &alpha.to_scalar());

        let e = &to_bigint(&Self::compute_range_proof_challenge(
            tag,
            stmt,
            msg_g_g,
            &z,
            &u,
            u1.as_ref(),
            &w,
        ));

        // s = r^e beta mod N
        let s = Randomness(
            wit.randomness
                .0
                .modpow(e, stmt.ek.0.n())
                .modmul(&beta.0, stmt.ek.0.n()),
        );

        // s1 = e * m + alpha
        let s1 = Plaintext(e * &msg_bigint.0 + &alpha.0);

        // s2 = e * rho + gamma
        let s2 = Randomness(e * &rho.0 + &gamma.0);

        (Proof { z, u, w, s, s1, s2 }, u1)
    }

    fn verify_range_proof_inner(
        &self,
        tag: u8,
        stmt: &Statement,
        proof: &Proof,
        msg_g_g_u1: Option<(
            &k256::ProjectivePoint,
            &k256::ProjectivePoint,
            &k256::ProjectivePoint,
        )>, // (msg_g, g, u1)
    ) -> bool {
        // Ensure c is in Z*_N^2
        if !member_of_mul_group(&stmt.ciphertext.0, stmt.ek.0.nn()) {
            warn!("range proof: ciphertext not in Z*_N^2");
            return false;
        }

        // Ensure z is in Z*_N~
        if !member_of_mul_group(&proof.z, self.n_tilde()) {
            warn!("range proof: z not in Z*_N~");
            return false;
        }

        // Ensure u is in Z*_N^2
        if !member_of_mul_group(&proof.u.0, stmt.ek.0.nn()) {
            warn!("range proof: u not in Z*_N^2");
            return false;
        }

        // Ensure w is in Z*_N~
        if !member_of_mul_group(&proof.w, self.n_tilde()) {
            warn!("range proof: w not in Z*_N~");
            return false;
        }

        // Ensure s is in Z*_N
        if !member_of_mul_group(&proof.s.0, stmt.ek.0.n()) {
            warn!("range proof: s not in Z*_N");
            return false;
        }

        // Ensure s1 is in Z_q^3
        // Note that the Appendix says to check for s1 <= q^3,
        // but it'll be equal with negligible probability from an honest user
        // and the soundness proof mentions s1 < q^3.
        if !member_of_mod(&proof.s1.0, &secp256k1_modulus_cubed()) {
            warn!("range proof: s1 not in Z_q^3");
            return false;
        }

        // Ensure s2 is in Z_(q^3 N~)
        // There's a 1/q probability that it exceeds that bound
        let q3_n_tilde = secp256k1_modulus_cubed() * self.n_tilde();
        if !member_of_mod(&proof.s2.0, &q3_n_tilde) {
            warn!("range proof: s2 not in Z_(q^3 N~)");
            return false;
        }

        // Ensure msg_g and u1 are points on secp256k1
        // This is handled by k256_serde on deserialize.

        let e = Self::compute_range_proof_challenge(
            tag,
            stmt,
            msg_g_g_u1.map(|(msg_g, g, _)| (msg_g, g)),
            &proof.z,
            &proof.u,
            msg_g_g_u1.map(|(_, _, u1)| u1),
            &proof.w,
        );

        let e_neg_bigint = to_bigint(&e).neg();
        let e_neg = e.negate();

        if let Some((msg_g, g, u1)) = msg_g_g_u1 {
            let s1 = to_scalar(&proof.s1.0);
            let s1_g = g * &s1;

            // u1 ?= g^s1 y^(-e)
            let u1_check = msg_g * &e_neg + s1_g;
            if u1_check != *u1 {
                warn!("range proof: 'wc' check failed, invalid u1");
                return false;
            }
        }

        // u ?= Paillier-Enc(s1, s) * c^(-e) mod N^2
        let u_check = stmt
            .ek
            .encrypt_with_randomness(&proof.s1, &proof.s)
            .0
            .modmul(
                &stmt.ciphertext.0.modpow(&e_neg_bigint, stmt.ek.0.nn()),
                stmt.ek.0.nn(),
            );
        if u_check != proof.u.0 {
            warn!("range proof: u check failed");
            return false;
        }

        // w ?= h1^s1 h2^s2 z^(-e) mod N~
        let w_check = self.commit(&proof.s1, &proof.s2).modmul(
            &proof.z.modpow(&e_neg_bigint, self.n_tilde()),
            self.n_tilde(),
        );
        if w_check != proof.w {
            warn!("range proof: w check failed");
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
    use crate::crypto_tools::k256_serde::ProjectivePoint;

    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        let proof = proof.clone();
        Proof {
            u: Ciphertext(proof.u.0 + BigNumber::one()),
            ..proof
        }
    }

    pub fn corrupt_proof_wc(proof_wc: &ProofWc) -> ProofWc {
        let proof_wc = proof_wc.clone();
        ProofWc {
            u1: ProjectivePoint::from(k256::ProjectivePoint::generator() + proof_wc.u1.as_ref()),
            ..proof_wc
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{collections::TypedUsize, crypto_tools::paillier::keygen_unsafe};

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
        let (ek, _dk) = &keygen_unsafe(&mut rand::thread_rng()).unwrap();
        let msg = &k256::Scalar::random(rand::thread_rng());
        let g = &k256::ProjectivePoint::generator();
        let msg_g = &(g * msg);
        let (ciphertext, randomness) = &ek.encrypt(&msg.into());
        let prover_id = TypedUsize::from_usize(10);
        let verifier_id = TypedUsize::from_usize(4);
        let bad_id = TypedUsize::from_usize(100);

        let stmt_wc = &StatementWc {
            stmt: Statement {
                prover_id,
                verifier_id,
                ciphertext,
                ek,
            },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { msg, randomness };
        let (zkp, _) = ZkSetup::new_unsafe(&mut rand::thread_rng(), &0_u32.to_be_bytes()).unwrap();

        // test: valid proof
        let proof = zkp.range_proof(stmt, wit);
        assert!(zkp.verify_range_proof(stmt, &proof));

        // test: valid proof wc (with check)
        let proof_wc = zkp.range_proof_wc(stmt_wc, wit).unwrap();
        assert!(zkp.verify_range_proof_wc(stmt_wc, &proof_wc));

        let mut bad_stmt_wc = &mut stmt_wc.clone();
        bad_stmt_wc.stmt.prover_id = verifier_id;
        bad_stmt_wc.stmt.verifier_id = prover_id;

        let mut bad_stmt = &mut bad_stmt_wc.stmt.clone();

        // test: valid proof and bad id
        assert!(!zkp.verify_range_proof(bad_stmt, &proof));
        bad_stmt.verifier_id = bad_id;
        assert!(!zkp.verify_range_proof(bad_stmt, &proof));

        // test: valid proof wc and bad id
        assert!(!zkp.verify_range_proof_wc(bad_stmt_wc, &proof_wc));
        bad_stmt_wc.stmt.verifier_id = bad_id;
        assert!(!zkp.verify_range_proof_wc(bad_stmt_wc, &proof_wc));

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        assert!(!zkp.verify_range_proof(stmt, &bad_proof));

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        assert!(!zkp.verify_range_proof_wc(stmt_wc, &bad_proof_wc));
        // test: bad witness
        let bad_wit = &Witness {
            msg: &(*wit.msg + k256::Scalar::one()),
            ..*wit
        };
        let bad_proof = zkp.range_proof(stmt, bad_wit);
        assert!(!zkp.verify_range_proof(stmt, &bad_proof));

        let bad_wit_proof_wc = zkp.range_proof_wc(stmt_wc, bad_wit).unwrap();
        assert!(!zkp.verify_range_proof_wc(stmt_wc, &bad_wit_proof_wc));
    }
}
