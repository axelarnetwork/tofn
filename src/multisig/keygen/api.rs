use crate::{
    collections::TypedUsize,
    crypto_tools::rng,
    sdk::{
        api::{PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::r1;
pub use super::secret_key_share::*;

/// Maximum byte length of messages exchanged during keygen.
pub const MAX_MSG_LEN: usize = 100;

pub use super::secret_key_share::*;
pub use rng::SecretRecoveryKey;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenShareId;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyId;

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenShareId, KeygenPartyId, MAX_MSG_LEN>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenPartyShareCounts = PartyShareCounts<KeygenPartyId>;

// TODO use const generics for these bounds
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

/// Initialize a new keygen protocol
// #[allow(clippy::too_many_arguments)]
pub fn new_keygen(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    secret_recovery_key: &rng::SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeygenProtocol> {
    // TODO refactor arg validation code with gg20
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
    let my_keygen_id = party_share_counts.party_to_share_id(my_party_id, my_subshare_id)?;

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

    let round2 = r1::start(
        my_keygen_id,
        threshold,
        party_share_counts.clone(),
        secret_recovery_key,
        session_nonce,
    )?;

    new_protocol(party_share_counts, my_keygen_id, round2)
}
