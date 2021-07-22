use super::{KeygenPartyIndex, KeygenPartyShareCounts, RealKeygenPartyIndex, SecretRecoveryKey};
use crate::{
    k256_serde, paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        collections::{TypedUsize, VecMap},
        sdk::api::{TofnFatal, TofnResult},
    },
};
use hmac::{Hmac, Mac, NewMac};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::error;

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
    all_shares: VecMap<KeygenPartyIndex, SharePublicInfo>,
}

/// `SharePublicInfo` public info unique to each share
/// all parties store a list of `SharePublicInfo`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SharePublicInfo {
    X_i: k256_serde::ProjectivePoint,
    ek: paillier_k256::EncryptionKey,
    zkp: paillier_k256::zk::ZkSetup,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret but it's stored here anyway
/// because it's an essential part of secret data
/// and parties need a way to know their own index
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShareSecretInfo {
    index: TypedUsize<KeygenPartyIndex>,
    dk: paillier_k256::DecryptionKey,
    x_i: k256_serde::Scalar,
}

/// Subset of `SecretKeyShare` that goes on-chain.
/// (Secret data is encrypted so it's ok to post publicly.)
/// When combined with similar data from all parties,
/// this data + mnemonic can be used to recover a full `SecretKeyShare` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareRecoveryInfo {
    index: TypedUsize<KeygenPartyIndex>,
    share: SharePublicInfo,
    x_i_ciphertext: paillier_k256::Ciphertext,
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
    pub fn all_shares(&self) -> &VecMap<KeygenPartyIndex, SharePublicInfo> {
        &self.all_shares
    }
    pub(super) fn new(
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
        y: k256_serde::ProjectivePoint,
        all_shares: VecMap<KeygenPartyIndex, SharePublicInfo>,
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
    pub fn ek(&self) -> &paillier_k256::EncryptionKey {
        &self.ek
    }
    pub fn zkp(&self) -> &paillier_k256::zk::ZkSetup {
        &self.zkp
    }
    pub(super) fn new(
        X_i: k256_serde::ProjectivePoint,
        ek: paillier_k256::EncryptionKey,
        zkp: paillier_k256::zk::ZkSetup,
    ) -> Self {
        Self { X_i, ek, zkp }
    }
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenPartyIndex> {
        self.index
    }
    pub(super) fn new(
        index: TypedUsize<KeygenPartyIndex>,
        dk: paillier_k256::DecryptionKey,
        x_i: k256_serde::Scalar,
    ) -> Self {
        Self { index, dk, x_i }
    }

    // expose secret info only in tests `#[cfg(test)]` and never outside this crate `pub(super)`
    // TODO: #[cfg(test)]  // We need this in R1
    pub(crate) fn x_i(&self) -> &k256_serde::Scalar {
        &self.x_i
    }

    pub(crate) fn dk(&self) -> &paillier_k256::DecryptionKey {
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
    pub fn recover(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        recovery_infos: &[KeyShareRecoveryInfo],
        party_id: TypedUsize<RealKeygenPartyIndex>,
        subshare_id: usize, // in 0..party_share_counts[party_id]
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
    ) -> TofnResult<Self> {
        // basic argument validation
        if session_nonce.is_empty() {
            error!("invalid session_nonce length: {}", session_nonce.len());
            return Err(TofnFatal);
        }
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
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut ChaCha20Rng::from_seed(rng_seed(
            secret_recovery_key,
            session_nonce,
        )));

        // verify recovery of the correct Paillier keys
        if ek != recovery_infos_sorted[share_id.as_usize()].share.ek {
            error!("recovered ek mismatch for index {}", share_id);
            return Err(TofnFatal);
        }

        // prepare output
        let x_i = dk
            .decrypt(&recovery_infos_sorted[share_id.as_usize()].x_i_ciphertext)
            .to_scalar()
            .into();
        let y = vss_k256::recover_secret_commit(
            &recovery_infos_sorted
                .iter()
                .map(|info| {
                    vss_k256::ShareCommit::from_point(info.share.X_i.clone(), info.index.as_usize())
                })
                .collect::<Vec<_>>(),
            threshold,
        )
        .into();
        let all_shares: VecMap<KeygenPartyIndex, SharePublicInfo> = recovery_infos_sorted
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

fn rng_seed(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> <ChaCha20Rng as SeedableRng>::Seed {
    let mut prf = Hmac::<Sha256>::new(secret_recovery_key[..].into());
    prf.update(session_nonce);
    prf.finalize().into_bytes().into()
}
