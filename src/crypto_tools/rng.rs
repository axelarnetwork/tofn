use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

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

    prf.update(&tag.to_be_bytes());
    prf.update(&party_id.to_bytes());
    prf.update(session_nonce);

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}

/// Initialize a RNG by hashing the arguments.
/// Intended for use generating a ECDSA signing key.
pub(crate) fn rng_seed_ecdsa_signing_key(
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

    let mut prf = Hmac::<Sha256>::new(secret_recovery_key.0[..].into());

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
    tag: u8,
    signing_key: &k256::Scalar,
    message_digest: &k256::Scalar,
) -> TofnResult<impl CryptoRng + RngCore> {
    let mut signing_key_bytes = signing_key.to_bytes();
    let msg_to_sign_bytes = message_digest.to_bytes();

    let mut prf = Hmac::<Sha256>::new(&Default::default());

    prf.update(&tag.to_be_bytes());
    prf.update(&signing_key_bytes);
    prf.update(&msg_to_sign_bytes);

    signing_key_bytes.zeroize();

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}
