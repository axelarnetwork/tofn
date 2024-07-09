use hmac::{Mac, SimpleHmac};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use tracing::error;
use zeroize::Zeroize;

use crate::sdk::{
    api::{TofnFatal, TofnResult},
    key::SecretRecoveryKey,
};

const SESSION_NONCE_LENGTH_MIN: usize = 4;
const SESSION_NONCE_LENGTH_MAX: usize = 256;

/// Initialize a RNG by hashing the arguments.
/// Intended for use generating a ECDSA signing key.
pub(crate) fn rng_seed_signing_key(
    protocol_tag: u8,
    tag: u8,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<impl CryptoRng + RngCore> {
    if session_nonce.len() < SESSION_NONCE_LENGTH_MIN
        || session_nonce.len() > SESSION_NONCE_LENGTH_MAX
    {
        error!(
            "invalid session_nonce length {} not in [{},{}]",
            session_nonce.len(),
            SESSION_NONCE_LENGTH_MIN,
            SESSION_NONCE_LENGTH_MAX
        );
        return Err(TofnFatal);
    }

    let mut prf =
        SimpleHmac::<Sha256>::new_from_slice(&secret_recovery_key.0[..]).map_err(|_| {
            error!("failure to initialize hmac");
            TofnFatal
        })?;

    prf.update(&protocol_tag.to_be_bytes());
    prf.update(&tag.to_be_bytes());
    prf.update(session_nonce);

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

/// Initialize a RNG by hashing the arguments.
/// Intended for use generating an ephemeral scalar for ECDSA signatures in the spirit of RFC 6979,
/// except this implementation does not conform to RFC 6979.
/// Compare with RustCrypto: <https://github.com/RustCrypto/signatures/blob/54925be85d4eeb0540bf7c687ab08152a858871a/ecdsa/src/rfc6979.rs#L16-L40>
#[cfg(feature = "secp256k1")]
pub(crate) fn rng_seed_ecdsa_ephemeral_scalar(
    protocol_tag: u8,
    tag: u8,
    signing_key: &k256::Scalar,
    message_digest: &k256::Scalar,
) -> TofnResult<impl CryptoRng + RngCore> {
    let mut signing_key_bytes = signing_key.to_bytes();
    let msg_to_sign_bytes = message_digest.to_bytes();

    let mut prf = SimpleHmac::<Sha256>::new(&Default::default());

    prf.update(&protocol_tag.to_be_bytes());
    prf.update(&tag.to_be_bytes());
    prf.update(&signing_key_bytes);
    prf.update(&msg_to_sign_bytes);

    signing_key_bytes.zeroize();

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto_tools::{
            message_digest::MessageDigest,
            rng::{rng_seed_ecdsa_ephemeral_scalar, rng_seed_signing_key},
        },
        sdk::key::SecretRecoveryKey,
    };

    use crypto_bigint::ArrayEncoding;
    use ecdsa::elliptic_curve::ops::Reduce;
    use k256::U256;
    use rand::RngCore;

    /// Check rng outputs against golden files to catch regressions (such as on updating deps).
    /// Golden files were generated from tofn commit corresponding to tofnd v0.10.1 release
    #[test]
    fn rng_seed_signing_key_known_vectors() {
        struct TestCase {
            protocol_tag: u8,
            tag: u8,
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
        }

        let test_cases = vec![
            TestCase {
                protocol_tag: 0,
                tag: 0,
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
            },
            TestCase {
                protocol_tag: 0x01,
                tag: 0x02,
                secret_recovery_key: SecretRecoveryKey([0x11; 64]),
                session_nonce: vec![0xAA, 0xBB, 0xCC, 0xDD],
            },
        ];

        let expected_outputs: Vec<_> = test_cases
            .into_iter()
            .map(|test_case| {
                let mut rng = rng_seed_signing_key(
                    test_case.protocol_tag,
                    test_case.tag,
                    &test_case.secret_recovery_key,
                    &test_case.session_nonce,
                )
                .expect("Failed to initialize RNG");

                let mut output = [0u8; 32];
                rng.fill_bytes(&mut output);

                hex::encode(output)
            })
            .collect();

        goldie::assert_json!(expected_outputs);
    }

    /// Check rng outputs against golden files to catch regressions (such as on updating deps).
    /// Golden files were generated from tofn commit corresponding to tofnd v0.10.1 release
    #[test]
    fn rng_seed_ecdsa_ephemeral_scalar_known_vectors() {
        struct TestCase {
            protocol_tag: u8,
            tag: u8,
            signing_key: [u8; 32],
            message_digest: MessageDigest,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                protocol_tag: 0,
                tag: 0,
                signing_key: [0; 32],
                message_digest: MessageDigest::from([0; 32]),
            },
            TestCase {
                protocol_tag: 0,
                tag: 0,
                signing_key: [1; 32],
                message_digest: MessageDigest::from([2; 32]),
            },
            TestCase {
                protocol_tag: 1,
                tag: 2,
                signing_key: [255; 32],
                message_digest: MessageDigest::from([255; 32]),
            },
        ];

        let expected_outputs: Vec<_> = test_cases
            .into_iter()
            .map(|test_case| {
                let signing_key =
                    k256::Scalar::reduce(U256::from_be_byte_array(test_case.signing_key.into()));

                let mut rng = rng_seed_ecdsa_ephemeral_scalar(
                    test_case.protocol_tag,
                    test_case.tag,
                    &signing_key,
                    &k256::Scalar::from(&test_case.message_digest),
                )
                .expect("Failed to initialize RNG");

                let mut output = [0u8; 32];
                rng.fill_bytes(&mut output);

                hex::encode(output)
            })
            .collect();

        goldie::assert_json!(expected_outputs);
    }
}
