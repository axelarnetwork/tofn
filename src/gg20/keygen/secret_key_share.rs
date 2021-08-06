use super::{KeygenPartyId, KeygenPartyShareCounts, KeygenShareId, PartyKeyPair};
use crate::{
    collections::{TypedUsize, VecMap},
    gg20::crypto_tools::{k256_serde, paillier, vss},
    sdk::api::{TofnFatal, TofnResult},
};
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
pub struct KeyShareRecoveryInfo {
    index: TypedUsize<KeygenShareId>,
    share: SharePublicInfo,
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
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.y.bytes()
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

    pub fn recovery_info(&self) -> TofnResult<KeyShareRecoveryInfo> {
        let index = self.share.index;
        let share = self.group.all_shares.get(index)?.clone();
        let x_i_ciphertext = share.ek.encrypt(&self.share.x_i.unwrap().into()).0;
        Ok(KeyShareRecoveryInfo {
            index,
            share,
            x_i_ciphertext,
        })
    }

    /// Recover a `SecretKeyShare`
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        party_keypair: &PartyKeyPair,
        recovery_infos: &[KeyShareRecoveryInfo],
        party_id: TypedUsize<KeygenPartyId>,
        subshare_id: usize, // in 0..party_share_counts[party_id]
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
    ) -> TofnResult<Self> {
        let share_count = recovery_infos.len();
        let share_id = party_share_counts.party_to_share_id(party_id, subshare_id)?;
        if threshold >= share_count || share_id.as_usize() >= share_count {
            error!(
                "invalid (share_count,threshold,index): ({},{},{})",
                share_count, threshold, share_id
            );
            return Err(TofnFatal);
        }
        if share_count != party_share_counts.total_share_count() {
            error!("party_share_counts and recovery_infos disagree on total share count",);
            return Err(TofnFatal);
        }

        // sort recovery_info and verify indices are 0..len-1
        let recovery_infos_sorted = {
            let mut recovery_infos_sorted = recovery_infos.to_vec();
            recovery_infos_sorted.sort_unstable_by_key(|r| r.index.as_usize());
            for (i, info) in recovery_infos_sorted.iter().enumerate() {
                if info.index.as_usize() != i {
                    error!(
                        "invalid party index {} at sorted position {}",
                        info.index, i
                    );
                    return Err(TofnFatal);
                }
            }
            recovery_infos_sorted
        };

        // recover my Paillier keys
        let ek = &party_keypair.ek;
        let dk = party_keypair.dk.clone();

        // verify recovery of the correct Paillier keys
        if ek != &recovery_infos_sorted[share_id.as_usize()].share.ek {
            error!("recovered ek mismatch for index {}", share_id);
            return Err(TofnFatal);
        }

        // prepare output
        let x_i = dk
            .decrypt(&recovery_infos_sorted[share_id.as_usize()].x_i_ciphertext)
            .to_scalar()
            .into();
        let y = vss::recover_secret_commit(
            &recovery_infos_sorted
                .iter()
                .map(|info| {
                    vss::ShareCommit::from_point(info.share.X_i.clone(), info.index.as_usize())
                })
                .collect::<Vec<_>>(),
            threshold,
        )
        .into();
        let all_shares: VecMap<KeygenShareId, SharePublicInfo> = recovery_infos_sorted
            .into_iter()
            .map(|info| SharePublicInfo {
                X_i: info.share.X_i,
                ek: info.share.ek,
                zkp: info.share.zkp,
            })
            .collect();

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
                x_i,
            },
        })
    }

    // super::super so it's visible in sign
    // TODO change file hierarchy so that you need only pub(super)
    pub(in super::super) fn new(group: GroupPublicInfo, share: ShareSecretInfo) -> Self {
        Self { group, share }
    }
}
