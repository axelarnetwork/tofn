use super::{KeygenPartyIndex, SecretRecoveryKey};
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

/// final output of keygen
/// store this struct in tofnd kvstore
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyShare {
    pub group: GroupPublicInfo,
    pub share: ShareSecretInfo,
}

/// `GroupPublicInfo` is the same for all shares
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupPublicInfo {
    pub(crate) threshold: usize,
    pub(crate) y: k256_serde::ProjectivePoint,
    pub(crate) all_shares: VecMap<KeygenPartyIndex, SharePublicInfo>,
}

impl GroupPublicInfo {
    pub fn share_count(&self) -> usize {
        self.all_shares.len()
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.y.bytes()
    }
}

/// `SharePublicInfo` public info unique to each share
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SharePublicInfo {
    pub(crate) X_i: k256_serde::ProjectivePoint,
    pub(crate) ek: paillier_k256::EncryptionKey,
    pub(crate) zkp: paillier_k256::zk::ZkSetup,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret; it's just convenient to put it here
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShareSecretInfo {
    pub(crate) index: TypedUsize<KeygenPartyIndex>,
    pub(crate) dk: paillier_k256::DecryptionKey,
    pub(crate) x_i: k256_serde::Scalar,
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenPartyIndex> {
        self.index
    }
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

impl SecretKeyShare {
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
    /// TODO more complete arg checking? eg. unique eks, etc
    pub fn recover(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        recovery_infos: &[KeyShareRecoveryInfo],
        index: TypedUsize<KeygenPartyIndex>,
        threshold: usize,
    ) -> TofnResult<Self> {
        // basic argument validation
        if session_nonce.is_empty() {
            error!("invalid session_nonce length: {}", session_nonce.len());
            return Err(TofnFatal);
        }
        let share_count = recovery_infos.len();
        if threshold >= share_count || index.as_usize() >= share_count {
            error!(
                "invalid (share_count,threshold,index): ({},{},{})",
                share_count, threshold, index
            );
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
        if ek != recovery_infos_sorted[index.as_usize()].share.ek {
            error!("recovered ek mismatch for index {}", index);
            return Err(TofnFatal);
        }

        // prepare output
        let x_i = dk
            .decrypt(&recovery_infos_sorted[index.as_usize()].x_i_ciphertext)
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
                threshold,
                y,
                all_shares,
            },
            share: ShareSecretInfo { index, dk, x_i },
        })
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
