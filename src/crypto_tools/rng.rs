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
