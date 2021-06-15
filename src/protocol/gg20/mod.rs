use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

use crate::{k256_serde, paillier_k256};
use serde::{Deserialize, Serialize};

/// sign only 32-byte hash digests
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDigest([u8; 32]);

impl TryFrom<&[u8]> for MessageDigest {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

impl From<&MessageDigest> for k256::Scalar {
    fn from(v: &MessageDigest) -> Self {
        k256::Scalar::from_bytes_reduced(k256::FieldBytes::from_slice(&v.0[..]))
    }
}

/// final output of keygen
/// store this struct in tofnd kvstore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyShare {
    pub group: GroupPublicInfo,
    pub share: ShareSecretInfo,
}

/// `GroupPublicInfo` is the same for all shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPublicInfo {
    share_count: usize,
    threshold: usize,
    y_k256: k256_serde::ProjectivePoint,
    all_shares: Vec<SharePublicInfo>,
}

impl GroupPublicInfo {
    pub fn share_count(&self) -> usize {
        self.share_count
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.y_k256.bytes()
    }
}

/// `SharePublicInfo` public info unique to each share
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SharePublicInfo {
    y_i: k256_serde::ProjectivePoint,
    ek: paillier_k256::EncryptionKey,
    zkp: paillier_k256::zk::ZkSetup,
}

/// `ShareSecretInfo` secret info unique to each share
/// `my_index` is not secret; it's just convenient to put it here
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSecretInfo {
    my_index: usize,
    dk_k256: paillier_k256::DecryptionKey,
    my_x_i_k256: k256_serde::Scalar,
}

impl ShareSecretInfo {
    pub fn index(&self) -> usize {
        self.my_index
    }
}

pub mod keygen;
pub mod sign;
mod vss_k256;

#[cfg(test)]
mod tests;
