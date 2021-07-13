use crate::refactor::api::{Protocol, TofnResult};
use crate::refactor::collections::{Behave, TypedUsize};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::implementer_api::{ProtocolBuilder, Round};

// need to derive all this crap for each new marker struct
// in order to avoid this problem: https://stackoverflow.com/a/31371094
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyIndex;
impl Behave for KeygenPartyIndex {}

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenPartyIndex>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenPartyIndex>;
pub type SecretRecoveryKey = [u8; 64];

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

pub const MAX_SHARE_COUNT: usize = 1000;

pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    index: TypedUsize<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: Behaviour,
) -> TofnResult<KeygenProtocol> {
    new_keygen_impl(
        share_count,
        threshold,
        index,
        secret_recovery_key,
        session_nonce,
        #[cfg(feature = "malicious")]
        behaviour,
    )
}

fn new_keygen_impl(
    share_count: usize,
    threshold: usize,
    index: TypedUsize<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: Behaviour,
) -> TofnResult<KeygenProtocol> {
    // validate args
    if share_count <= threshold || share_count <= index.as_usize() || share_count > MAX_SHARE_COUNT
    {
        error!(
            "invalid (share_count,threshold,index): ({},{},{})",
            share_count, threshold, index
        );
        return Err(());
    }
    if session_nonce.is_empty() {
        error!("invalid session_nonce length: {}", session_nonce.len());
        return Err(());
    }

    // compute the RNG seed now so as to minimize copying of `secret_recovery_key`
    let rng_seed = rng::seed(secret_recovery_key, session_nonce);

    Ok(Protocol::NotDone(Round::new_no_messages(
        Box::new(r1::R1 {
            threshold,
            rng_seed,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
        share_count,
        index,
    )?))
}

mod r1;
mod r2;
mod r3;
mod r4;
mod rng;
mod secret_key_share;
pub use secret_key_share::{GroupPublicInfo, SecretKeyShare, SharePublicInfo, ShareSecretInfo};

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen

#[cfg(feature = "malicious")]
pub mod malicious;
#[cfg(feature = "malicious")]
use malicious::Behaviour;
