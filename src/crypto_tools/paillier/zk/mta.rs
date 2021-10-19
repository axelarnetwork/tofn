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

use super::{secp256k1_modulus_cubed, secp256k1_modulus_squared};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub prover_id: TypedUsize<SignShareId>,
    pub verifier_id: TypedUsize<SignShareId>,
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
    z: BigNumber,
    z_prime: BigNumber,
    t: BigNumber,
    v: BigNumber,
    w: BigNumber,
    s: Randomness,
    s1: Plaintext,
    s2: Randomness,
    t1: Plaintext,
    t2: Randomness,
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

    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    /// Compute the challenge e in Z_q for the range proof
    fn compute_mta_proof_challenge(
        tag: u8,
        stmt: &Statement,
        x_g: Option<&k256::ProjectivePoint>, // (x_g)
        z: &BigNumber,
        z_prime: &BigNumber,
        t: &BigNumber,
        u: Option<&k256::ProjectivePoint>,
        v: &BigNumber,
        w: &BigNumber,
    ) -> k256::Scalar {
        let e = k256::Scalar::from_digest(
            Sha256::new()
                .chain(tag.to_be_bytes())
                .chain(stmt.prover_id.to_bytes())
                .chain(stmt.verifier_id.to_bytes())
                .chain(stmt.ek.0.n().to_bytes())
                .chain(stmt.ciphertext1.0.to_bytes())
                .chain(stmt.ciphertext2.0.to_bytes())
                .chain(x_g.map_or([0; 33], |x_g| k256_serde::point_to_bytes(x_g)))
                .chain(z.to_bytes())
                .chain(z_prime.to_bytes())
                .chain(t.to_bytes())
                .chain(u.map_or([0; 33], |u| k256_serde::point_to_bytes(u)))
                .chain(v.to_bytes())
                .chain(w.to_bytes()),
        );

        e
    }

    #[allow(clippy::many_single_char_names)]
    fn mta_proof_inner(
        &self,
        tag: u8,
        stmt: &Statement,
        x_g: Option<&k256::ProjectivePoint>,
        wit: &Witness,
    ) -> (Proof, Option<k256::ProjectivePoint>) {
        // Assume: x in Z_q
        debug_assert!(member_of_mod(&to_bigint(wit.x), &secp256k1_modulus()));

        // Assume: y in Z_N
        debug_assert!(member_of_mod(&wit.msg.0, stmt.ek.0.n()));

        // Assume: r in Z*_N
        debug_assert!(member_of_mul_group(&wit.randomness.0, stmt.ek.0.n()));

        // Assume: c1 in Z*_N^2
        debug_assert!(member_of_mul_group(&stmt.ciphertext1.0, stmt.ek.0.nn()));

        // Assume: c2 in Z*_N^2
        debug_assert!(member_of_mul_group(&stmt.ciphertext2.0, stmt.ek.0.nn()));

        // Assume: X = g^x
        if let Some(x_g) = x_g {
            debug_assert!(*x_g == k256::ProjectivePoint::generator() * wit.x);
        }

        let alpha = Plaintext::generate(&secp256k1_modulus_cubed());

        let q_n_tilde = secp256k1_modulus() * self.n_tilde();
        let q3_n_tilde = secp256k1_modulus_cubed() * self.n_tilde();

        let sigma = Randomness::generate(&q_n_tilde);
        let tau = Randomness::generate(&q_n_tilde);
        let rho = Randomness::generate(&q_n_tilde);

        let rho_prime = Randomness::generate(&q3_n_tilde);

        let beta = stmt.ek.sample_randomness();
        let gamma = Plaintext(stmt.ek.sample_randomness().0.to_owned());

        let x = Plaintext(to_bigint(wit.x));

        // z = h1^m h2^rho mod N~
        let z = self.commit(&x, &rho);

        // z' = h1^alpha h2^rho' mod N~
        let z_prime = self.commit(&alpha, &rho_prime);

        // t = h1^y h2^sigma mod N~
        let t = self.commit(wit.msg, &sigma);

        // u = g^alpha
        let u = x_g.map::<k256::ProjectivePoint, _>(|_| {
            k256::ProjectivePoint::generator() * to_scalar(&alpha.0)
        });

        // v = c1^alpha Paillier-Enc(gamma, beta) mod N^2
        let v = stmt.ek.encrypt_with_randomness(&gamma, &beta).0.modmul(
            &stmt.ciphertext1.0.modpow(&alpha.0, stmt.ek.0.nn()),
            stmt.ek.0.nn(),
        );

        // w = h1^gamma h2^tau mod N~
        let w = self.commit(&gamma, &tau);

        let e = &to_bigint(&Self::compute_mta_proof_challenge(
            tag,
            stmt,
            x_g,
            &z,
            &z_prime,
            &t,
            u.as_ref(),
            &v,
            &w,
        ));

        // s = r^e beta mod N
        let s = Randomness(
            wit.randomness
                .0
                .modpow(e, stmt.ek.0.n())
                .modmul(&beta.0, stmt.ek.0.n()),
        );

        // The following computations are done over the integers (as opposed to integers modulo n)
        // s1 = e x + alpha
        let s1 = Plaintext(e * &x.0 + &alpha.0);

        // s2 = e rho + rho'
        let s2 = Randomness(e * &rho.0 + &rho_prime.0);

        // t1 = e y + gamma
        let t1 = Plaintext(e * &wit.msg.0 + &gamma.0);

        // t2 = e sigma + tau
        let t2 = Randomness(e * &sigma.0 + &tau.0);

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
        // Ensure c1 is in Z*_N^2
        if !member_of_mul_group(&stmt.ciphertext1.0, stmt.ek.0.nn()) {
            warn!("mta proof: c1 not in Z*_N^2");
            return false;
        }

        // Ensure c2 is in Z*_N^2
        if !member_of_mul_group(&stmt.ciphertext2.0, stmt.ek.0.nn()) {
            warn!("mta proof: c2 not in Z*_N^2");
            return false;
        }

        // Ensure z is in Z*_N~
        if !member_of_mul_group(&proof.z, self.n_tilde()) {
            warn!("mta proof: z not in Z*_N~");
            return false;
        }

        // Ensure z' is in Z*_N~
        if !member_of_mul_group(&proof.z_prime, self.n_tilde()) {
            warn!("mta proof: z' not in Z*_N~");
            return false;
        }

        // Ensure t is in Z*_N~
        if !member_of_mul_group(&proof.t, self.n_tilde()) {
            warn!("mta proof: t not in Z*_N~");
            return false;
        }

        // Ensure v is in Z*_N^2
        if !member_of_mul_group(&proof.v, stmt.ek.0.nn()) {
            warn!("mta proof: v not in Z*_N^2");
            return false;
        }

        // Ensure w is in Z*_N~
        if !member_of_mul_group(&proof.w, self.n_tilde()) {
            warn!("mta proof: w not in Z*_N~");
            return false;
        }

        // Ensure s is in Z*_N
        if !member_of_mul_group(&proof.s.0, stmt.ek.0.n()) {
            warn!("mta proof: s not in Z*_N");
            return false;
        }

        // Ensure s1 is in Z_q^3
        // Note that the Appendix says to check for s1 <= q^3,
        // but it'll be equal with negligible probability from an honest user
        // and the soundness proof mentions s1 < q^3.
        if !member_of_mod(&proof.s1.0, &secp256k1_modulus_cubed()) {
            warn!("mta proof: s1 not in Z_q^3");
            return false;
        }

        // Ensure s2 is in Z_(q^3 N~)
        let q3_n_tilde = secp256k1_modulus_cubed() * self.n_tilde();
        if !member_of_mod(&proof.s2.0, &q3_n_tilde) {
            warn!("mta proof: s2 not in Z_(q^3 N~)");
            return false;
        }

        // Ensure t1 is in Z_(q N) - {0} (since 0 != gamma in Z*_N, t1 = e y + gamma)
        let q_n = secp256k1_modulus() * stmt.ek.0.n();
        if proof.t1.0 == BigNumber::zero() || !member_of_mod(&proof.t1.0, &q_n) {
            warn!("mta proof: t1 not in Z_(q N)");
            return false;
        }

        // Ensure t2 is in Z_(q^2 N~)
        let q2_n_tilde = &secp256k1_modulus_squared() * self.n_tilde();
        if !member_of_mod(&proof.t2.0, &q2_n_tilde) {
            warn!("mta proof: t2 not in Z_(q^2 N~)");
            return false;
        }

        // Ensure x_g and u are points on secp256k1
        // This is handled by k256_serde on deserialize.

        let e = Self::compute_mta_proof_challenge(
            tag,
            stmt,
            x_g_u.map(|(x_g, _)| x_g),
            &proof.z,
            &proof.z_prime,
            &proof.t,
            x_g_u.map(|(_, u)| u),
            &proof.v,
            &proof.w,
        );
        let e_bigint = to_bigint(&e);

        // g^s1 ?= X^e u
        if let Some((x_g, u)) = x_g_u {
            let s1 = to_scalar(&proof.s1.0);
            let s1_g = k256::ProjectivePoint::generator() * s1;
            let s1_g_check = x_g * &e + u;
            if s1_g_check != s1_g {
                warn!("mta proof: 'wc' check failed, invalid (g^x, u, s1)");
                return false;
            }
        }

        // h1^s1 h2^s2 ?= z^e z' mod N~
        let z_e_z_prime = proof
            .z
            .modpow(&e_bigint, self.n_tilde())
            .modmul(&proof.z_prime, self.n_tilde());
        let z_e_z_prime_check = self.commit(&proof.s1, &proof.s2);
        if z_e_z_prime_check != z_e_z_prime {
            warn!("mta proof: z^e z_prime check failed");
            return false;
        }

        // h1^t1 h2^t2 ?= t^e w mod N~
        let t_e_w = proof
            .t
            .modpow(&e_bigint, self.n_tilde())
            .modmul(&proof.w, self.n_tilde());
        let t_e_w_check = self.commit(&proof.t1, &proof.t2);
        if t_e_w_check != t_e_w {
            warn!("mta proof: t^e w check failed");
            return false;
        }

        // c1^s1 s^N Gamma^t1 ?= c2^e v mod N^2
        let cipher_check_lhs = stmt
            .ek
            .encrypt_with_randomness(&proof.t1, &proof.s)
            .0
            .modmul(
                &stmt.ciphertext1.0.modpow(&proof.s1.0, stmt.ek.0.nn()),
                stmt.ek.0.nn(),
            );
        let cipher_check_rhs = proof.v.modmul(
            &stmt.ciphertext2.0.modpow(&e_bigint, stmt.ek.0.nn()),
            stmt.ek.0.nn(),
        );
        if cipher_check_lhs != cipher_check_rhs {
            warn!("mta proof: cipher check failed");
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
            v: proof.v + BigNumber::from(1),
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
        BigNumber, Proof, Statement, StatementWc, Witness, ZkSetup,
    };
    use crate::{
        collections::TypedUsize,
        crypto_tools::paillier::{keygen_unsafe, Ciphertext, Plaintext},
    };
    use ecdsa::elliptic_curve::Field;
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn basic_correctness() {
        // create a (statement, witness) pair
        let (ek, _dk) = &keygen_unsafe(&mut rand::thread_rng()).unwrap();
        let msg = &Plaintext(ek.sample_randomness().0.clone());
        let x = &k256::Scalar::random(rand::thread_rng());
        let x_g = &(k256::ProjectivePoint::generator() * x);
        let randomness = &ek.sample_randomness();
        let ciphertext1 = &Ciphertext(BigNumber::random(ek.0.nn()));
        let ciphertext2 = &ek.add(
            &ek.mul(ciphertext1, &Plaintext::from_scalar(x)),
            &ek.encrypt_with_randomness(msg, randomness),
        );
        let prover_id = TypedUsize::from_usize(1);
        let verifier_id = TypedUsize::from_usize(4);
        let bad_id = TypedUsize::from_usize(100);

        let stmt_wc = &StatementWc {
            stmt: Statement {
                prover_id,
                verifier_id,
                ciphertext1,
                ciphertext2,
                ek,
            },
            x_g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { x, msg, randomness };
        let (zkp, _) = ZkSetup::new_unsafe(&mut rand::thread_rng(), &0_u32.to_be_bytes()).unwrap();

        // test: valid proof
        let proof = zkp.mta_proof(stmt, wit);
        assert!(zkp.verify_mta_proof(stmt, &proof));

        // test: valid proof wc (with check)
        let proof_wc = zkp.mta_proof_wc(stmt_wc, wit).unwrap();
        assert!(zkp.verify_mta_proof_wc(stmt_wc, &proof_wc));

        let mut bad_stmt_wc = &mut stmt_wc.clone();
        bad_stmt_wc.stmt.prover_id = verifier_id;
        bad_stmt_wc.stmt.verifier_id = prover_id;

        let mut bad_stmt = &mut bad_stmt_wc.stmt.clone();

        // test: valid proof and bad id
        assert!(!zkp.verify_mta_proof(bad_stmt, &proof));
        bad_stmt.verifier_id = bad_id;
        assert!(!zkp.verify_mta_proof(bad_stmt, &proof));

        // test: valid proof with large length
        assert!(!zkp.verify_mta_proof(
            stmt,
            &Proof {
                z_prime: proof.z_prime.clone() + zkp.n_tilde(),
                ..proof.clone()
            }
        ));

        // test: valid proof wc and bad id
        assert!(!zkp.verify_mta_proof_wc(bad_stmt_wc, &proof_wc));
        bad_stmt_wc.stmt.verifier_id = bad_id;
        assert!(!zkp.verify_mta_proof_wc(bad_stmt_wc, &proof_wc));

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        assert!(!zkp.verify_mta_proof(stmt, &bad_proof));
        assert!(!zkp.verify_mta_proof(bad_stmt, &bad_proof));

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        assert!(!zkp.verify_mta_proof_wc(stmt_wc, &bad_proof_wc));
        assert!(!zkp.verify_mta_proof_wc(bad_stmt_wc, &bad_proof_wc));

        // test: bad witness
        let bad_wit = &Witness {
            msg: &Plaintext(&wit.msg.0 + BigNumber::one()),
            ..*wit
        };
        let bad_wit_proof = zkp.mta_proof(stmt, bad_wit);
        assert!(!zkp.verify_mta_proof(stmt, &bad_wit_proof));

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = zkp.mta_proof_wc(stmt_wc, bad_wit).unwrap();
        assert!(!zkp.verify_mta_proof_wc(stmt_wc, &bad_wit_proof_wc));
    }
}
