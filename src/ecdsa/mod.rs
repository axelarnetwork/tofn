use std::convert::TryInto;

use ecdsa::{
    elliptic_curve::{sec1::ToEncodedPoint, Field},
    hazmat::{SignPrimitive, VerifyPrimitive},
};
use message_digest::MessageDigest;
use tracing::error;

use crate::{
    constants::ECDSA_TAG,
    crypto_tools::{k256_serde, message_digest, rng},
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        key::SecretRecoveryKey,
    },
};

#[derive(Debug)]
pub struct KeyPair {
    signing_key: k256_serde::SecretScalar,
    encoded_verifying_key: [u8; 33], // SEC1-encoded compressed curve point
}

impl KeyPair {
    /// SEC1-encoded compressed curve point.
    /// tofnd needs to return this to axelar-core.
    pub fn encoded_verifying_key(&self) -> &[u8; 33] {
        &self.encoded_verifying_key
    }

    /// tofnd needs to store this in the kv store.
    pub fn signing_key(&self) -> &k256_serde::SecretScalar {
        &self.signing_key
    }
}

pub fn keygen(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let rng = rng::rng_seed_signing_key(ECDSA_TAG, KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    let signing_key = k256_serde::SecretScalar::random(rng);

    // TODO make this work with k256_serde::ProjectivePoint::to_bytes
    let encoded_verifying_key = k256_serde::ProjectivePoint::from(&signing_key)
        .as_ref()
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| {
            error!("failure to convert ecdsa verifying key to 33-byte array");
            TofnFatal
        })?;

    Ok(KeyPair {
        signing_key,
        encoded_verifying_key,
    })
}

/// Returns a ASN.1 DER-encoded ECDSA signature.
/// These signatures have variable byte length so we must return a [BytesVec] instead of a [u8] array.
pub fn sign(
    signing_key: &k256_serde::SecretScalar,
    message_digest: &MessageDigest,
) -> TofnResult<BytesVec> {
    let signing_key = signing_key.as_ref();
    let message_digest_scalar = k256::Scalar::from(message_digest);

    let rng = rng::rng_seed_ecdsa_ephemeral_scalar(
        ECDSA_TAG,
        SIGN_TAG,
        signing_key,
        &message_digest_scalar,
    )?;
    let ephemeral_scalar = k256::Scalar::random(rng);

    let signature = k256_serde::Signature::from(
        signing_key
            .try_sign_prehashed(ephemeral_scalar, &message_digest_scalar.to_bytes())
            .map_err(|_| {
                error!("failure to sign");
                TofnFatal
            })
            .map(|(r, _)| r)?,
    );

    Ok(signature.to_bytes())
}

pub fn verify(
    encoded_verifying_key: &[u8; 33],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    let verifying_key =
        k256_serde::ProjectivePoint::from_bytes(encoded_verifying_key).ok_or(TofnFatal)?;
    let signature = k256::ecdsa::Signature::from_der(encoded_signature).map_err(|_| TofnFatal)?;

    Ok(verifying_key
        .as_ref()
        .to_affine()
        .verify_prehashed(&k256::FieldBytes::from(message_digest), &signature)
        .is_ok())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;
const SIGN_TAG: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::sdk::key::{dummy_secret_recovery_key, SecretRecoveryKey};

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = [42; 32].into();

        let key_pair = keygen(&dummy_secret_recovery_key(42), b"tofn nonce").unwrap();
        let encoded_signature = sign(key_pair.signing_key(), &message_digest).unwrap();
        let success = verify(
            key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(success);
    }

    /// Check keygen/signing outputs against known vectors to catch regressions (such as on updating deps).
    /// Known vectors were generated from tofn commit corresponding to tofnd v0.10.1 release
    #[test]
    fn keygen_sign_known_vectors() {
        struct TestCase {
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
            message_digest: [u8; 32],
            expected_signing_key: Vec<u8>,
            expected_verifying_key: Vec<u8>,
            expected_signature: Vec<u8>,
        }

        let test_cases = vec![
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
                message_digest: [42; 32],
                expected_signing_key: vec![
                    178, 195, 90, 168, 218, 224, 244, 241, 22, 212, 134, 206, 49, 137, 57, 138,
                    175, 204, 132, 22, 121, 4, 175, 173, 27, 119, 145, 174, 104, 1, 204, 121,
                ],
                expected_verifying_key: vec![
                    2, 246, 184, 67, 10, 45, 112, 93, 220, 139, 26, 229, 48, 5, 46, 162, 97, 131,
                    170, 102, 114, 63, 46, 53, 179, 167, 215, 210, 19, 253, 188, 182, 65,
                ],
                expected_signature: vec![
                    48, 68, 2, 32, 55, 67, 30, 153, 65, 188, 47, 219, 11, 121, 191, 80, 110, 97,
                    224, 58, 33, 170, 233, 242, 173, 87, 109, 227, 167, 28, 150, 137, 49, 62, 87,
                    205, 2, 32, 119, 170, 189, 3, 234, 15, 17, 116, 22, 195, 36, 163, 183, 165, 94,
                    250, 245, 149, 93, 96, 224, 61, 29, 56, 157, 41, 187, 149, 216, 169, 196, 122,
                ],
            },
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0xff; 64]),
                session_nonce: vec![0xff; 32],
                message_digest: [0xff; 32],
                expected_signing_key: vec![
                    20, 0, 197, 123, 117, 125, 190, 14, 195, 142, 6, 244, 108, 51, 142, 49, 183,
                    192, 157, 104, 94, 167, 185, 231, 91, 127, 73, 196, 41, 34, 146, 121,
                ],
                expected_verifying_key: vec![
                    3, 91, 141, 151, 206, 207, 158, 244, 130, 143, 119, 0, 127, 148, 235, 116, 106,
                    163, 0, 247, 219, 238, 136, 51, 212, 102, 129, 19, 59, 245, 118, 93, 63,
                ],
                expected_signature: vec![
                    48, 68, 2, 32, 62, 44, 34, 73, 116, 181, 52, 82, 255, 15, 237, 134, 90, 25, 24,
                    214, 211, 169, 77, 253, 1, 240, 130, 198, 10, 16, 66, 48, 141, 59, 113, 152, 2,
                    32, 57, 103, 40, 179, 179, 188, 120, 172, 61, 181, 138, 128, 75, 180, 209, 156,
                    225, 83, 186, 247, 159, 113, 135, 44, 18, 74, 100, 226, 136, 59, 142, 194,
                ],
            },
        ];

        for test_case in test_cases {
            let keypair = keygen(&test_case.secret_recovery_key, &test_case.session_nonce).unwrap();

            assert_eq!(
                keypair.signing_key().as_ref().to_bytes().to_vec(),
                test_case.expected_signing_key
            );
            assert_eq!(
                keypair.encoded_verifying_key().to_vec(),
                test_case.expected_verifying_key
            );

            let signature = sign(keypair.signing_key(), &test_case.message_digest.into()).unwrap();
            assert_eq!(signature, test_case.expected_signature);

            let success = verify(
                keypair.encoded_verifying_key(),
                &test_case.message_digest.into(),
                &signature,
            )
            .unwrap();
            assert!(success);
        }
    }
}
