use super::{r1, rng};
use crate::refactor::collections::TypedUsize;
use crate::refactor::protocol::api::{Protocol, Round, TofnResult};
use crate::refactor::protocol::implementer_api::{ProtocolBuilder, ProtocolInfoDeluxe};
use crate::{k256_serde, paillier_k256, refactor::collections::VecMap};
use serde::{Deserialize, Serialize};
use tracing::error;

#[cfg(feature = "malicious")]
use super::malicious;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyIndex; // TODO actually a keygen subshare index

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RealKeygenPartyIndex; // TODO the real keygen party index

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenPartyIndex, RealKeygenPartyIndex>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenPartyIndex>;
pub type SecretRecoveryKey = [u8; 64];

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

pub const MAX_SHARE_COUNT: usize = 1000;

/// Initialize a new keygen protocol
pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    index: TypedUsize<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
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

    // TODO TEMPORARY one share per party
    let party_share_counts = (0..share_count).map(|_| 1).collect();

    Ok(Protocol::NotDone(Round::new_no_messages(
        Box::new(r1::R1 {
            threshold,
            rng_seed,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
        ProtocolInfoDeluxe::new(party_share_counts, index),
    )?))
}
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
