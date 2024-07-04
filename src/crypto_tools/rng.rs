use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

use ecdsa::elliptic_curve::generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use tracing::error;
use zeroize::Zeroize;

use crate::{
    collections::TypedUsize,
    sdk::api::{TofnFatal, TofnResult},
};

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretRecoveryKey(pub(crate) [u8; 64]);

impl TryFrom<&[u8]> for SecretRecoveryKey {
    type Error = TryFromSliceError;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

const SESSION_NONCE_LENGTH_MIN: usize = 4;
const SESSION_NONCE_LENGTH_MAX: usize = 256;

pub(crate) fn rng_seed<K>(
    tag: u8,
    party_id: TypedUsize<K>,
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

    let mut prf = Hmac::<Sha256>::new(secret_recovery_key.0[..].into());

    // TODO: Use protocol domain separation: https://github.com/axelarnetwork/tofn/issues/184
    prf.update(&tag.to_be_bytes());
    prf.update(&party_id.to_bytes());
    prf.update(session_nonce);

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

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

    // Take care not to copy [secret_recovery_key]
    // This explicit declaration ensures that we use the following reference-to-reference conversion:
    // https://docs.rs/generic-array/0.14.4/src/generic_array/lib.rs.html#553-563
    let hmac_key: &GenericArray<_, _> = (&secret_recovery_key.0[..]).into();

    let mut prf = Hmac::<Sha256>::new(hmac_key);

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
pub(crate) fn rng_seed_ecdsa_ephemeral_scalar_with_party_id<K>(
    tag: u8,
    party_id: TypedUsize<K>,
    signing_key: &k256::Scalar,
    msg_to_sign: &k256::Scalar,
) -> TofnResult<impl CryptoRng + RngCore> {
    let mut signing_key_bytes = signing_key.to_bytes();
    let msg_to_sign_bytes = msg_to_sign.to_bytes();

    let mut prf = Hmac::<Sha256>::new(&Default::default());

    // TODO: Use protocol domain separation: https://github.com/axelarnetwork/tofn/issues/184
    prf.update(&tag.to_be_bytes());
    prf.update(&party_id.to_bytes());
    prf.update(&signing_key_bytes);
    prf.update(&msg_to_sign_bytes);

    signing_key_bytes.zeroize();

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

/// Initialize a RNG by hashing the arguments.
/// Intended for use generating an ephemeral scalar for ECDSA signatures in the spirit of RFC 6979,
/// except this implementation does not conform to RFC 6979.
/// Compare with RustCrypto: <https://github.com/RustCrypto/signatures/blob/54925be85d4eeb0540bf7c687ab08152a858871a/ecdsa/src/rfc6979.rs#L16-L40>
pub(crate) fn rng_seed_ecdsa_ephemeral_scalar(
    protocol_tag: u8,
    tag: u8,
    signing_key: &k256::Scalar,
    message_digest: &k256::Scalar,
) -> TofnResult<impl CryptoRng + RngCore> {
    let mut signing_key_bytes = signing_key.to_bytes();
    let msg_to_sign_bytes = message_digest.to_bytes();

    let mut prf = Hmac::<Sha256>::new(&Default::default());

    prf.update(&protocol_tag.to_be_bytes());
    prf.update(&tag.to_be_bytes());
    prf.update(&signing_key_bytes);
    prf.update(&msg_to_sign_bytes);

    signing_key_bytes.zeroize();

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

#[cfg(test)]
/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key(index: usize) -> SecretRecoveryKey {
    let index_bytes = index.to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    SecretRecoveryKey(result)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_seed_signing_key_known_vectors() {
        struct TestCase {
            protocol_tag: u8,
            tag: u8,
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
            expected_output: [u8; 32],
        }

        let test_cases = vec![
            TestCase {
                protocol_tag: 0,
                tag: 0,
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
                expected_output: [
                    178, 195, 90, 168, 218, 224, 244, 241, 22, 212, 134, 206, 49, 137, 57, 138,
                    175, 204, 132, 22, 121, 4, 175, 173, 27, 119, 145, 174, 104, 1, 204, 121,
                ],
            },
            TestCase {
                protocol_tag: 0x01,
                tag: 0x02,
                secret_recovery_key: SecretRecoveryKey([0x11; 64]),
                session_nonce: vec![0xAA, 0xBB, 0xCC, 0xDD],
                expected_output: [
                    195, 251, 156, 25, 253, 219, 100, 153, 17, 181, 174, 140, 167, 35, 103, 217,
                    158, 164, 189, 241, 128, 100, 57, 12, 109, 144, 130, 212, 6, 255, 90, 56,
                ],
            },
        ];

        for test_case in test_cases {
            let mut rng = rng_seed_signing_key(
                test_case.protocol_tag,
                test_case.tag,
                &test_case.secret_recovery_key,
                &test_case.session_nonce,
            )
            .expect("Failed to initialize RNG");

            let mut output = [0u8; 32];
            rng.fill_bytes(&mut output);

            assert_eq!(output, test_case.expected_output);
        }
    }


    #[test]
    fn rng_seed_ecdsa_ephemeral_scalar_known_vectors() {
        struct TestCase {
            protocol_tag: u8,
            tag: u8,
            signing_key: k256::Scalar,
            message_digest: k256::Scalar,
            expected_output: [u8; 32],
        }

        let test_cases = vec![
            TestCase {
                protocol_tag: 0,
                tag: 0,
                signing_key: k256::Scalar::from_bytes_reduced(&[0; 32].into()),
                message_digest: k256::Scalar::from_bytes_reduced(&[0; 32].into()),
                expected_output: [42, 244, 242, 58, 19, 84, 31, 121, 130, 37, 135, 111, 107, 172, 251, 213, 74, 30, 235, 53, 166, 76, 21, 34, 197, 232, 120, 78, 112, 230, 226, 123],
            },
            TestCase {
                protocol_tag: 0,
                tag: 0,
                signing_key: k256::Scalar::from_bytes_reduced(&[1; 32].into()),
                message_digest: k256::Scalar::from_bytes_reduced(&[2; 32].into()),
                expected_output: [114, 196, 139, 208, 156, 99, 210, 57, 81, 207, 137, 119, 190, 163, 38, 157, 231, 107, 201, 6, 70, 109, 193, 33, 80, 74, 17, 33, 220, 160, 216, 40],
            },
            TestCase {
                protocol_tag: 1,
                tag: 2,
                signing_key: k256::Scalar::from_bytes_reduced(&[255; 32].into()),
                message_digest: k256::Scalar::from_bytes_reduced(&[255; 32].into()),
                expected_output: [170, 189, 238, 222, 51, 5, 123, 112, 253, 104, 67, 99, 69, 239, 234, 10, 112, 225, 213, 0, 159, 175, 186, 10, 213, 159, 40, 39, 233, 46, 40, 156],
            },
        ];

        for test_case in test_cases {
            let mut rng = rng_seed_ecdsa_ephemeral_scalar(
                test_case.protocol_tag,
                test_case.tag,
                &test_case.signing_key,
                &test_case.message_digest,
            )
            .expect("Failed to initialize RNG");

            let mut output = [0u8; 32];
            rng.fill_bytes(&mut output);

            assert_eq!(output, test_case.expected_output);
        }
    }
}
