use super::{r1, rng, SecretKeyShare};
use crate::{
    collections::TypedUsize,
    sdk::{
        api::{PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[cfg(feature = "malicious")]
use super::malicious;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenShareId;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyId;

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenShareId, KeygenPartyId>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenPartyShareCounts = PartyShareCounts<KeygenPartyId>;
pub type SecretRecoveryKey = [u8; 64];

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

// TODO use const generics for these bounds
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

/// Initialize a new keygen protocol
pub fn new_keygen(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<KeygenProtocol> {
    new_keygen_impl(
        party_share_counts,
        threshold,
        my_party_id,
        my_subshare_id,
        secret_recovery_key,
        session_nonce,
        true,
        #[cfg(feature = "malicious")]
        behaviour,
    )
}

pub fn new_keygen_unsafe(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<KeygenProtocol> {
    new_keygen_impl(
        party_share_counts,
        threshold,
        my_party_id,
        my_subshare_id,
        secret_recovery_key,
        session_nonce,
        false,
        #[cfg(feature = "malicious")]
        behaviour,
    )
}

#[allow(clippy::too_many_arguments)]
fn new_keygen_impl(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    use_safe_primes: bool,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<KeygenProtocol> {
    // validate args
    if party_share_counts
        .iter()
        .any(|(_, &c)| c > MAX_PARTY_SHARE_COUNT)
    {
        error!(
            "detected a party with share count exceeding {}",
            MAX_PARTY_SHARE_COUNT
        );
        return Err(TofnFatal);
    }
    let total_share_count: usize = party_share_counts.total_share_count();
    let my_share_id = party_share_counts.party_to_share_id(my_party_id, my_subshare_id)?;

    #[allow(clippy::suspicious_operation_groupings)]
    if total_share_count <= threshold
        || total_share_count > MAX_TOTAL_SHARE_COUNT
        || my_party_id.as_usize() >= party_share_counts.party_count()
    {
        error!(
            "invalid (total_share_count, threshold, my_party_id, my_subshare_id, max_share_count): ({},{},{},{},{})",
            total_share_count, threshold, my_party_id, my_subshare_id, MAX_TOTAL_SHARE_COUNT
        );
        return Err(TofnFatal);
    }
    if session_nonce.is_empty() {
        error!("invalid session_nonce length: {}", session_nonce.len());
        return Err(TofnFatal);
    }

    // compute the RNG seed now so as to minimize copying of `secret_recovery_key`
    let rng_seed = rng::seed(secret_recovery_key, session_nonce);

    new_protocol(
        party_share_counts.clone(),
        my_share_id,
        Box::new(r1::R1 {
            threshold,
            party_share_counts,
            rng_seed,
            use_safe_primes,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
    )
}
