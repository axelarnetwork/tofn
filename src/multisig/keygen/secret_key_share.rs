use super::{KeygenPartyId, KeygenPartyShareCounts, KeygenShareId};
use crate::{
    collections::{TypedUsize, VecMap},
    crypto_tools::k256_serde,
    sdk::api::{BytesVec, TofnResult},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Keygen share output to be sent over the wire
/// TODO [encoded_pubkey] should be a `[u8; 33]` except `serde` doesn't support length-33 arrays
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeygenShare {
    pub encoded_pubkey: BytesVec, // SEC1-encoded secp256k1 curve point
    pub party_id: TypedUsize<KeygenPartyId>,
    pub subshare_id: usize,
}
/// final output of keygen: store this struct in tofnd kvstore
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyShare {
    group: GroupPublicInfo,
    share: ShareSecretInfo,
}

/// `GroupPublicInfo` is the same for all shares
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupPublicInfo {
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    all_pubkeys: VecMap<KeygenShareId, k256_serde::ProjectivePoint>,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret but it's stored here anyway
/// because it's an essential part of secret data
/// and parties need a way to know their own index
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ShareSecretInfo {
    index: TypedUsize<KeygenShareId>,
    signing_key: k256_serde::Scalar,
}

impl GroupPublicInfo {
    pub fn party_share_counts(&self) -> &KeygenPartyShareCounts {
        &self.party_share_counts
    }

    pub fn share_count(&self) -> usize {
        self.all_pubkeys.len()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn all_pubkeys(&self) -> &VecMap<KeygenShareId, k256_serde::ProjectivePoint> {
        &self.all_pubkeys
    }

    /// SEC1-encoded curve points
    /// tofnd can send this data through grpc
    pub fn all_encoded_pubkeys(&self) -> TofnResult<Vec<KeygenShare>> {
        self.all_pubkeys
            .iter()
            .map(|(share_id, pubkey)| {
                let (party_id, subshare_id) = self
                    .party_share_counts
                    .share_to_party_subshare_ids(share_id)?;
                Ok(KeygenShare {
                    encoded_pubkey: pubkey.to_bytes().to_vec(),
                    party_id,
                    subshare_id,
                })
            })
            .collect()
    }

    pub(super) fn new(
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
        all_pubkeys: VecMap<KeygenShareId, k256_serde::ProjectivePoint>,
    ) -> Self {
        Self {
            party_share_counts,
            threshold,
            all_pubkeys,
        }
    }
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenShareId> {
        self.index
    }

    pub(super) fn new(index: TypedUsize<KeygenShareId>, signing_key: k256_serde::Scalar) -> Self {
        Self { index, signing_key }
    }

    pub(crate) fn signing_key(&self) -> &k256_serde::Scalar {
        &self.signing_key
    }
}

impl SecretKeyShare {
    pub fn group(&self) -> &GroupPublicInfo {
        &self.group
    }

    pub fn share(&self) -> &ShareSecretInfo {
        &self.share
    }

    // super::super so it's visible in sign
    // TODO change file hierarchy so that you need only pub(super)
    pub(in super::super) fn new(group: GroupPublicInfo, share: ShareSecretInfo) -> Self {
        Self { group, share }
    }
}
