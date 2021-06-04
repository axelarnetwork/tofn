use crate::{k256_serde, paillier_k256};
use serde::{Deserialize, Serialize};

// final output of keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyShare {
    pub group: Group,
    pub share: Share,
}

/// `Group` contains only info that is identical across all keygen parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    share_count: usize,
    threshold: usize,
    y_k256: k256_serde::ProjectivePoint,
    all_y_i_k256: Vec<k256_serde::ProjectivePoint>,
    all_eks_k256: Vec<paillier_k256::EncryptionKey>,
    all_zkps_k256: Vec<paillier_k256::zk::ZkSetup>,
}

/// `Share` contains only info that is specific to this keygen share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    my_index: usize,
    dk_k256: paillier_k256::DecryptionKey,
    my_x_i_k256: k256_serde::Scalar,
}

pub mod keygen;
pub mod sign;
mod vss;
mod vss_k256;

#[cfg(test)]
mod tests;
