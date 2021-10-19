use super::{KeygenPartyId, KeygenPartyShareCounts, KeygenShareId, PartyKeyPair};
use crate::{
    collections::{TypedUsize, VecMap},
    crypto_tools::{k256_serde, paillier, vss},
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        implementer_api::{decode, encode},
    },
};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use tracing::error;
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
    y: k256_serde::ProjectivePoint,
    all_shares: VecMap<KeygenShareId, SharePublicInfo>,
}

/// `SharePublicInfo` public info unique to each share
/// all parties store a list of `SharePublicInfo`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SharePublicInfo {
    X_i: k256_serde::ProjectivePoint,
    ek: paillier::EncryptionKey,
    zkp: paillier::zk::ZkSetup,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret but it's stored here anyway
/// because it's an essential part of secret data
/// and parties need a way to know their own index
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ShareSecretInfo {
    index: TypedUsize<KeygenShareId>,
    dk: paillier::DecryptionKey,
    x_i: k256_serde::Scalar,
}

/// Subset of `SecretKeyShare` that goes on-chain.
/// (Secret data is encrypted so it's ok to post publicly.)
/// When combined with similar data from all parties,
/// this data + mnemonic can be used to recover a full `SecretKeyShare` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyShareRecoveryInfo {
    x_i_ciphertext: paillier::Ciphertext,
}

impl GroupPublicInfo {
    pub fn party_share_counts(&self) -> &KeygenPartyShareCounts {
        &self.party_share_counts
    }

    pub fn share_count(&self) -> usize {
        self.all_shares.len()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// SEC1-encoded curve point
    /// tofnd can send this data through grpc
    /// TODO change return type to `[u8; 33]`?
    pub fn encoded_pubkey(&self) -> BytesVec {
        self.y.to_bytes().to_vec()
    }

    pub fn all_shares_bytes(&self) -> TofnResult<BytesVec> {
        encode(&self.all_shares)
    }

    pub fn y(&self) -> &k256_serde::ProjectivePoint {
        &self.y
    }

    pub fn all_shares(&self) -> &VecMap<KeygenShareId, SharePublicInfo> {
        &self.all_shares
    }

    pub(super) fn new(
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
        y: k256_serde::ProjectivePoint,
        all_shares: VecMap<KeygenShareId, SharePublicInfo>,
    ) -> Self {
        Self {
            party_share_counts,
            threshold,
            y,
            all_shares,
        }
    }
}

#[allow(non_snake_case)]
impl SharePublicInfo {
    pub fn X_i(&self) -> &k256_serde::ProjectivePoint {
        &self.X_i
    }

    pub fn ek(&self) -> &paillier::EncryptionKey {
        &self.ek
    }

    pub fn zkp(&self) -> &paillier::zk::ZkSetup {
        &self.zkp
    }

    pub(super) fn new(
        X_i: k256_serde::ProjectivePoint,
        ek: paillier::EncryptionKey,
        zkp: paillier::zk::ZkSetup,
    ) -> Self {
        Self { X_i, ek, zkp }
    }
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenShareId> {
        self.index
    }

    pub(super) fn new(
        index: TypedUsize<KeygenShareId>,
        dk: paillier::DecryptionKey,
        x_i: k256_serde::Scalar,
    ) -> Self {
        Self { index, dk, x_i }
    }

    pub(crate) fn x_i(&self) -> &k256_serde::Scalar {
        &self.x_i
    }

    pub(crate) fn dk(&self) -> &paillier::DecryptionKey {
        &self.dk
    }
}

impl SecretKeyShare {
    pub fn group(&self) -> &GroupPublicInfo {
        &self.group
    }

    pub fn share(&self) -> &ShareSecretInfo {
        &self.share
    }

    pub fn recovery_info(&self) -> TofnResult<BytesVec> {
        let index = self.share.index;
        let share = self.group.all_shares.get(index)?;
        let x_i_ciphertext = share.ek.encrypt(&self.share.x_i.as_ref().into()).0;

        encode(&KeyShareRecoveryInfo { x_i_ciphertext })
    }

    /// Recover a `SecretKeyShare`
    /// We trust that group_info_bytes and pubkey_bytes are the values computed
    /// by the majority of the parties.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        party_keypair: &PartyKeyPair,
        recovery_info_bytes: &[u8],
        group_info_bytes: &[u8],
        pubkey_bytes: &[u8],
        party_id: TypedUsize<KeygenPartyId>,
        subshare_id: usize, // in 0..party_share_counts[party_id]
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
    ) -> TofnResult<Self> {
        let share_count = party_share_counts.total_share_count();
        let share_id = party_share_counts.party_to_share_id(party_id, subshare_id)?;

        if threshold >= share_count || share_id.as_usize() >= share_count {
            error!(
                "invalid (share_count,threshold,index): ({},{},{})",
                share_count, threshold, share_id
            );
            return Err(TofnFatal);
        }

        let recovery_info: KeyShareRecoveryInfo = decode(recovery_info_bytes).ok_or_else(|| {
            error!(
                "peer {} says: failed to deserialize recovery info",
                share_id
            );
            TofnFatal
        })?;

        // Since we trust group_info_bytes, we expect the order of all_shares to be correct
        let all_shares: VecMap<KeygenShareId, SharePublicInfo> = decode(group_info_bytes)
            .ok_or_else(|| {
                error!(
                    "peer {} says: failed to deserialize public share info",
                    share_id
                );
                TofnFatal
            })?;

        if all_shares.len() != share_count {
            error!(
                "peer {} says: only received {} public shares, expected {}",
                share_id,
                all_shares.len(),
                share_count
            );
            return Err(TofnFatal);
        }

        // recover my Paillier keys
        let ek = &party_keypair.ek;
        let dk = party_keypair.dk.clone();

        // verify recovery of the correct Paillier keys
        if ek != &all_shares.get(share_id)?.ek {
            error!("peer {} says: recovered ek mismatch", share_id);
            return Err(TofnFatal);
        }

        // prepare output
        let x_i = dk.decrypt(&recovery_info.x_i_ciphertext).to_scalar();

        // verify recovery of x_i using X_i
        #[allow(non_snake_case)]
        let X_i = &(ProjectivePoint::generator() * x_i);

        if X_i != all_shares.get(share_id)?.X_i.as_ref() {
            error!("peer {} says: recovered X_i mismatch", share_id);
            return Err(TofnFatal);
        }

        let share_commits = &all_shares
            .iter()
            .map(|(keygen_id, info)| {
                vss::ShareCommit::from_point(keygen_id.as_usize(), info.X_i.clone())
            })
            .collect::<Vec<_>>();

        // verify that the provided pubkey matches the group key from the public shares
        let y = vss::recover_secret_commit(share_commits, threshold)?.into();
        let pub_key = k256_serde::ProjectivePoint::from_bytes(pubkey_bytes).ok_or_else(|| {
            error!("peer {} says: failed to decode group public key", share_id);
            TofnFatal
        })?;

        if y != pub_key {
            error!(
                "peer {} says: recovered group public key mismatch",
                share_id
            );
            return Err(TofnFatal);
        }

        // NOTE: We're assuming that all_shares[share_id].zkp is correct
        // Verifying this would require regenerating the safe keypair for the ZkSetup too
        // And doesn't provide much benefit since we already trust the group_info_bytes

        Ok(Self {
            group: GroupPublicInfo {
                party_share_counts,
                threshold,
                y,
                all_shares,
            },
            share: ShareSecretInfo {
                index: share_id,
                dk,
                x_i: x_i.into(),
            },
        })
    }

    // super::super so it's visible in sign
    // TODO change file hierarchy so that you need only pub(super)
    pub(in super::super) fn new(group: GroupPublicInfo, share: ShareSecretInfo) -> Self {
        Self { group, share }
    }
}
