use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use tracing::error;

use crate::sdk::api::{TofnFatal, TofnResult};

use super::SecretRecoveryKey;

pub(crate) fn rng_seed(
    tag: u8,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<impl CryptoRng + RngCore> {
    // TODO: Enforce a sufficient minimum length as a sanity check against collisions.
    // While reusing Paillier keys is not known to be insecure, there's also no security proof for it.
    // This task primarily requires a review of axelar-core to see if it's providing long random nonces.
    if session_nonce.is_empty() {
        error!("invalid session_nonce length: {}", session_nonce.len());
        return Err(TofnFatal);
    }

    let mut prf = Hmac::<Sha256>::new(secret_recovery_key.0[..].into());

    prf.update(&tag.to_le_bytes());
    prf.update(session_nonce);

    let seed = prf.finalize().into_bytes().into();

    Ok(ChaCha20Rng::from_seed(seed))
}
