use crate::{
    collections::{HoleVecMap, Subset, TypedUsize, VecMap},
    gg20::keygen::{
        GroupPublicInfo, KeygenPartyId, KeygenShareId, SecretKeyShare, ShareSecretInfo,
    },
    sdk::{
        api::{BytesVec, PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::r1;

#[cfg(feature = "malicious")]
use super::malicious;

pub use crate::crypto_tools::message_digest::MessageDigest;

/// Maximum byte length of messages exchanged during sign.
/// The sender of a message larger than this maximum will be accused as a faulter.
/// View all message sizes in the logs of the integration test `single_thred::basic_correctness`.
/// The largest sign message is r2::P2pHappy with size ~6828 bytes on the wire.
pub const MAX_MSG_LEN: usize = 7500;

pub type SignProtocol = Protocol<BytesVec, SignShareId, SignPartyId, MAX_MSG_LEN>;
pub type SignProtocolBuilder = ProtocolBuilder<BytesVec, SignShareId>;

// This includes all shares participating in the current signing protocol
pub type KeygenShareIds = VecMap<SignShareId, TypedUsize<KeygenShareId>>;
// This includes all shares (excluding self) participating in the current signing protocol
pub type Peers = HoleVecMap<SignShareId, TypedUsize<KeygenShareId>>;
// This is the set of parties participating in the current signing protocol
pub type SignParties = Subset<KeygenPartyId>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignShareId;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignPartyId;

/// Initialize a new sign protocol
/// Assume `group`, `share` are valid and check `sign_parties` against it.
pub fn new_sign(
    group: &GroupPublicInfo,
    share: &ShareSecretInfo,
    sign_parties: &SignParties,
    msg_to_sign: &MessageDigest,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<SignProtocol> {
    let all_keygen_ids =
        VecMap::from_vec(group.party_share_counts().share_id_subset(sign_parties)?);

    // participant share count must be at least threshold + 1
    if all_keygen_ids.len() <= group.threshold() {
        error!(
            "not enough participant shares: threshold [{}], participants [{}]",
            group.threshold(),
            all_keygen_ids.len(),
        );
        return Err(TofnFatal);
    }

    // find my keygen share_id
    let my_sign_id = all_keygen_ids
        .iter()
        .find(|(_, &k)| k == share.index())
        .map(|(s, _)| s)
        .ok_or_else(|| {
            error!("my keygen share_id {} is not a participant", share.index());
            TofnFatal
        })?;

    let sign_party_share_counts =
        PartyShareCounts::from_vec(group.party_share_counts().subset(sign_parties)?)?;

    let round2 = r1::start(
        my_sign_id,
        SecretKeyShare::new(group.clone(), share.clone()),
        msg_to_sign.into(),
        all_keygen_ids,
        #[cfg(feature = "malicious")]
        behaviour,
    )?;

    new_protocol(sign_party_share_counts, my_sign_id, round2)
}
