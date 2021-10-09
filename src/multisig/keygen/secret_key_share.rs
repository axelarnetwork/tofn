use super::{KeygenPartyShareCounts, KeygenShareId};
use crate::{
    collections::{TypedUsize, VecMap},
    sdk::api::{BytesVec, TofnResult},
};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
    all_verifying_keys: VecMap<KeygenShareId, VerifyingKey>,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret but it's stored here anyway
/// because it's an essential part of secret data
/// and parties need a way to know their own index
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ShareSecretInfo {
    index: TypedUsize<KeygenShareId>,
    signing_key: SigningKey,
}

impl GroupPublicInfo {
    pub fn party_share_counts(&self) -> &KeygenPartyShareCounts {
        &self.party_share_counts
    }

    pub fn share_count(&self) -> usize {
        self.all_verifying_keys.len()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn pubkey_bytes(&self) -> BytesVec {
        todo!()
    }

    pub fn all_shares_bytes(&self) -> TofnResult<BytesVec> {
        // encode(&self.all_shares)
        todo!()
    }

    pub fn all_verifying_keys(&self) -> &VecMap<KeygenShareId, VerifyingKey> {
        &self.all_verifying_keys
    }

    pub(super) fn new(
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
        all_verifying_keys: VecMap<KeygenShareId, VerifyingKey>,
    ) -> Self {
        Self {
            party_share_counts,
            threshold,
            all_verifying_keys,
        }
    }
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenShareId> {
        self.index
    }

    pub(super) fn new(index: TypedUsize<KeygenShareId>, signing_key: SigningKey) -> Self {
        Self { index, signing_key }
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
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
