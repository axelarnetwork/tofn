use crate::paillier_k256::{
    zk::{mta, ZkSetup},
    Ciphertext, EncryptionKey, Plaintext, Randomness,
};

#[derive(Debug)]
pub(crate) struct Secret {
    pub(crate) beta: k256::Scalar,
    pub(crate) beta_prime: Plaintext,
    pub(crate) beta_prime_randomness: Randomness,
}

pub(crate) fn mta_response(
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> (Ciphertext, Secret) {
    let beta_prime = a_ek.random_plaintext();
    let (beta_prime_ciphertext, beta_prime_randomness) = a_ek.encrypt(&beta_prime);
    let c_b = a_ek.add(
        &a_ek.mul(a_ciphertext, &Plaintext::from_scalar(b)),
        &beta_prime_ciphertext,
    );
    let beta = beta_prime.to_scalar().negate();
    (
        c_b,
        Secret {
            beta,
            beta_prime,
            beta_prime_randomness,
        },
    )
}

pub(crate) fn mta_response_with_proof(
    a_zkp: &ZkSetup,
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> (Ciphertext, mta::Proof, Secret) {
    let (c_b, s) = mta_response(a_ek, a_ciphertext, b);
    let proof = a_zkp.mta_proof(
        &mta::Statement {
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

pub(crate) fn mta_response_with_proof_wc(
    a_zkp: &ZkSetup,
    a_ek: &EncryptionKey,
    a_ciphertext: &Ciphertext,
    b: &k256::Scalar,
) -> (Ciphertext, mta::ProofWc, Secret) {
    let (c_b, s) = mta_response(a_ek, a_ciphertext, b);
    let proof_wc = a_zkp.mta_proof_wc(
        &mta::StatementWc {
            stmt: mta::Statement {
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
    );
    (c_b, proof_wc, s)
}

#[cfg(test)]
pub(crate) mod tests {
    use ecdsa::elliptic_curve::Field;

    use super::mta_response_with_proof_wc;
    use crate::paillier_k256::{
        keygen_unsafe,
        zk::{mta, range, ZkSetup},
    };

    #[test]
    fn basic_correctness() {
        let a = k256::Scalar::random(rand::thread_rng());
        let b = k256::Scalar::random(rand::thread_rng());
        let b_g = k256::ProjectivePoint::generator() * b;
        let (a_ek, a_dk) = keygen_unsafe();
        let a_zkp = ZkSetup::new_unsafe();
        let b_zkp = ZkSetup::new_unsafe();

        // MtA step 1: party a
        let (a_ciphertext, a_randomness) = a_ek.encrypt(&(&a).into());
        let a_range_proof = b_zkp.range_proof(
            &range::Statement {
                ciphertext: &a_ciphertext,
                ek: &a_ek,
            },
            &range::Witness {
                msg: &a,
                randomness: &a_randomness,
            },
        );

        // MtA step 2: party b (this module)
        b_zkp
            .verify_range_proof(
                &range::Statement {
                    ciphertext: &a_ciphertext,
                    ek: &a_ek,
                },
                &a_range_proof,
            )
            .unwrap();
        let (c_b, b_mta_proof_wc, b_secret) =
            mta_response_with_proof_wc(&a_zkp, &a_ek, &a_ciphertext, &b);

        // MtA step 3: party a
        a_zkp
            .verify_mta_proof_wc(
                &mta::StatementWc {
                    stmt: mta::Statement {
                        ciphertext1: &a_ciphertext,
                        ciphertext2: &c_b,
                        ek: &a_ek,
                    },
                    x_g: &b_g,
                },
                &b_mta_proof_wc,
            )
            .unwrap();
        let alpha = a_dk.decrypt_with_randomness(&c_b).0.to_scalar();

        // test: a * b = alpha + beta
        assert_eq!(a * b, alpha + b_secret.beta);
    }
}
