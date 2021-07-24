use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zeroize::Zeroize;

use super::SecretRecoveryKey;

#[derive(Debug, Zeroize, Clone)]
#[zeroize(drop)]
pub struct Seed(<ChaCha20Rng as SeedableRng>::Seed);

pub fn seed(secret_recovery_key: &SecretRecoveryKey, session_nonce: &[u8]) -> Seed {
    let mut prf = Hmac::<Sha256>::new(secret_recovery_key[..].into());
    prf.update(session_nonce);
    Seed(prf.finalize().into_bytes().into())
}

pub fn rng_from_seed(seed: Seed) -> impl CryptoRng + RngCore {
    ChaCha20Rng::from_seed(seed.0)
}

pub fn rng_seed(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> impl CryptoRng + RngCore {
    rng_from_seed(seed(secret_recovery_key, session_nonce))
}
