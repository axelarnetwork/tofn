use crate::{
    constants::ED25519_TAG,
    crypto_tools::{message_digest::MessageDigest, rng},
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        key::SecretRecoveryKey,
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};

#[derive(Debug)]
pub struct KeyPair(SigningKey);

impl KeyPair {
    pub fn encoded_verifying_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *self.0.verifying_key().as_bytes()
    }
}

pub fn keygen(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let mut rng =
        rng::rng_seed_signing_key(ED25519_TAG, KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    let signing_key = SigningKey::generate(&mut rng);

    Ok(KeyPair(signing_key))
}

/// Returns a Ed25519 signature.
/// The signature is encoded raw (R and S bytes) as a 64-byte array as per this [RFC](https://www.rfc-editor.org/rfc/rfc8032#section-3.3)
pub fn sign(signing_key: &KeyPair, message_digest: &MessageDigest) -> TofnResult<BytesVec> {
    Ok(signing_key
        .0
        .sign(message_digest.as_ref())
        .to_bytes()
        .into())
}

pub fn verify(
    encoded_verifying_key: &[u8; PUBLIC_KEY_LENGTH],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(encoded_verifying_key).map_err(|_| TofnFatal)?;

    let signature = Signature::from_slice(encoded_signature).map_err(|_| TofnFatal)?;

    Ok(verifying_key
        .verify_strict(message_digest.as_ref(), &signature)
        .is_ok())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::sdk::key::{dummy_secret_recovery_key, SecretRecoveryKey};

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = [42; 32].into();

        let key_pair = keygen(&dummy_secret_recovery_key(42), b"tofn nonce").unwrap();
        let mut encoded_signature = sign(&key_pair, &message_digest).unwrap();

        // Correct signature should verify
        let success = verify(
            &key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(success);

        // Tamper with the signature, it should no longer verify.
        *encoded_signature.last_mut().unwrap() += 1;

        let success = verify(
            &key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(!success);
    }

    /// Check keygen/signing outputs against golden files to catch regressions (such as on updating deps).
    /// Golden files were generated from tofn v0.2.0 release when ed25519 was added.
    #[test]
    fn keygen_sign_known_vectors() {
        struct TestCase {
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
            message_digest: [u8; 32],
        }

        let test_cases = vec![
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
                message_digest: [42; 32],
            },
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0xff; 64]),
                session_nonce: vec![0xff; 32],
                message_digest: [0xff; 32],
            },
        ];

        let expected_outputs: Vec<Vec<_>> = test_cases
            .into_iter()
            .map(|test_case| {
                let keypair =
                    keygen(&test_case.secret_recovery_key, &test_case.session_nonce).unwrap();
                let encoded_signing_key = keypair.0.to_bytes().into();
                let encoded_verifying_key = keypair.encoded_verifying_key().to_vec();

                let signature = sign(&keypair, &test_case.message_digest.into()).unwrap();

                let success = verify(
                    &keypair.encoded_verifying_key(),
                    &test_case.message_digest.into(),
                    &signature,
                )
                .unwrap();
                assert!(success);

                [encoded_signing_key, encoded_verifying_key, signature]
                    .into_iter()
                    .map(hex::encode)
                    .collect()
            })
            .collect();

        goldie::assert_json!(expected_outputs);
    }
}
