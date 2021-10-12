use crate::{
    collections::TypedUsize,
    crypto_tools::{
        k256_serde,
        paillier::{
            zk::{mta, ZkSetup},
            Ciphertext, EncryptionKey, Plaintext, Randomness,
        },
    },
    gg20::sign::SignShareId,
    sdk::api::TofnResult,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    pub beta: k256_serde::Scalar,
    pub beta_prime: Plaintext,
    pub beta_prime_randomness: Randomness,
}

pub fn mta_response(
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> (Ciphertext, Secret) {
    let beta_prime = a_ek.random_plaintext();
    let beta_prime_randomness = a_ek.sample_randomness();
    let (c_b, beta) =
        mta_response_from_randomness(a_ek, a_ciphertext, b, &beta_prime, &beta_prime_randomness);
    (
        c_b,
        Secret {
            beta,
            beta_prime,
            beta_prime_randomness,
        },
    )
}

pub fn mta_response_from_randomness(
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
    beta_prime: &Plaintext,
    beta_prime_randomness: &Randomness,
) -> (Ciphertext, k256_serde::Scalar) {
    let beta_prime_ciphertext = a_ek.encrypt_with_randomness(beta_prime, beta_prime_randomness);
    let c_b = a_ek.add(
        &a_ek.mul(a_ciphertext, &Plaintext::from_scalar(b)),
        &beta_prime_ciphertext,
    );
    let beta = k256_serde::Scalar::from(beta_prime.to_scalar().negate());
    (c_b, beta)
}

/// Return `true` iff `mta_response_from_randomness(a_ek, a_ciphertext, b, s.beta_prime, s.beta_randomness) == (c_b, s)`
pub fn verify_mta_response(
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
    c_b: &Ciphertext,
    s: &Secret,
) -> bool {
    let (check_c_b, check_beta) = mta_response_from_randomness(
        a_ek,
        a_ciphertext,
        b,
        &s.beta_prime,
        &s.beta_prime_randomness,
    );
    check_c_b == *c_b && check_beta == s.beta
}

pub fn mta_response_with_proof(
    prover_id: TypedUsize<SignShareId>,
    verifier_id: TypedUsize<SignShareId>,
    a_zkp: &ZkSetup,
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> (Ciphertext, mta::Proof, Secret) {
    let (c_b, s) = mta_response(a_ek, a_ciphertext, b);
    let proof = a_zkp.mta_proof(
        &mta::Statement {
            prover_id,
            verifier_id,
            ciphertext1: a_ciphertext,
            ciphertext2: &c_b,
            ek: a_ek,
        },
        &mta::Witness {
            x: b,
            msg: &s.beta_prime,
            randomness: &s.beta_prime_randomness,
        },
    );
    (c_b, proof, s)
}

pub fn mta_response_with_proof_wc(
    prover_id: TypedUsize<SignShareId>,
    verifier_id: TypedUsize<SignShareId>,
    a_zkp: &ZkSetup,
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> TofnResult<(Ciphertext, mta::ProofWc, Secret)> {
    let (c_b, s) = mta_response(a_ek, a_ciphertext, b);
    let proof_wc = a_zkp.mta_proof_wc(
        &mta::StatementWc {
            stmt: mta::Statement {
                prover_id,
                verifier_id,
                ciphertext1: a_ciphertext,
                ciphertext2: &c_b,
                ek: a_ek,
            },
            x_g: &(k256::ProjectivePoint::generator() * b),
        },
        &mta::Witness {
            x: b,
            msg: &s.beta_prime,
            randomness: &s.beta_prime_randomness,
        },
    )?;
    Ok((c_b, proof_wc, s))
}

#[cfg(test)]
mod tests {
    use ecdsa::elliptic_curve::Field;

    use super::{mta_response_with_proof_wc, verify_mta_response};
    use crate::{
        collections::TypedUsize,
        crypto_tools::paillier::{
            keygen_unsafe,
            zk::{mta, range, ZkSetup},
        },
    };

    #[test]
    fn basic_correctness() {
        let a = k256::Scalar::random(rand::thread_rng());
        let b = k256::Scalar::random(rand::thread_rng());
        let b_g = k256::ProjectivePoint::generator() * b;
        let (a_ek, a_dk) = keygen_unsafe(&mut rand::thread_rng()).unwrap();
        let (a_zkp, _) =
            ZkSetup::new_unsafe(&mut rand::thread_rng(), &0_u32.to_be_bytes()).unwrap();
        let (b_zkp, _) =
            ZkSetup::new_unsafe(&mut rand::thread_rng(), &1_u32.to_be_bytes()).unwrap();
        let a_id = TypedUsize::from_usize(0);
        let b_id = TypedUsize::from_usize(1);

        // MtA step 1: party a
        let (a_ciphertext, a_randomness) = a_ek.encrypt(&(&a).into());
        let a_range_proof = b_zkp.range_proof(
            &range::Statement {
                prover_id: a_id,
                verifier_id: b_id,
                ciphertext: &a_ciphertext,
                ek: &a_ek,
            },
            &range::Witness {
                msg: &a,
                randomness: &a_randomness,
            },
        );

        // MtA step 2: party b (this module)
        assert!(b_zkp.verify_range_proof(
            &range::Statement {
                prover_id: a_id,
                verifier_id: b_id,
                ciphertext: &a_ciphertext,
                ek: &a_ek,
            },
            &a_range_proof,
        ));
        let (c_b, b_mta_proof_wc, b_secret) =
            mta_response_with_proof_wc(a_id, b_id, &a_zkp, &a_ek, &a_ciphertext, &b).unwrap();

        // MtA step 3: party a
        assert!(a_zkp.verify_mta_proof_wc(
            &mta::StatementWc {
                stmt: mta::Statement {
                    prover_id: a_id,
                    verifier_id: b_id,
                    ciphertext1: &a_ciphertext,
                    ciphertext2: &c_b,
                    ek: &a_ek,
                },
                x_g: &b_g,
            },
            &b_mta_proof_wc,
        ));
        let alpha = a_dk.decrypt_with_randomness(&c_b).0.to_scalar();

        // test: correct MtA output: a * b = alpha + beta
        assert_eq!(a * b, alpha + b_secret.beta.as_ref());

        assert!(verify_mta_response(
            &a_ek,
            &a_ciphertext,
            &b,
            &c_b,
            &b_secret
        ));
    }
}
