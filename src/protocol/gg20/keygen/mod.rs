use crate::{fillvec::FillVec, protocol::MsgBytes, zkp::paillier::ZkSetup};
use curv::{FE, GE};
use paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};

// final output of keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyShare {
    pub share_count: usize,
    pub threshold: usize,
    pub my_index: usize,
    pub my_dk: DecryptionKey,
    pub my_ek: EncryptionKey,
    pub my_zkp: ZkSetup,
    pub ecdsa_public_key: GE,
    pub my_ecdsa_secret_key_share: FE,
    pub all_ecdsa_public_key_shares: Vec<GE>,
    pub all_eks: Vec<EncryptionKey>,
    pub all_zkps: Vec<ZkSetup>,
}

pub use curv::elliptic::curves::traits::{ECPoint, ECScalar};

enum Status {
    New,
    R1,
    R2,
    R3,
    R3Fail,
    Done,
    Fail,
}

#[cfg(feature = "malicious")]
pub mod malicious;

mod crimes;
mod protocol;
mod r1;
mod r2;
mod r3;
mod r4;
mod r4_fail;

pub struct Keygen {
    status: Status,

    // state data
    share_count: usize,
    threshold: usize,
    my_index: usize,
    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,

    // incoming messages
    in_r1bcasts: FillVec<r1::Bcast>,
    in_r2bcasts: FillVec<r2::Bcast>,
    in_all_r2p2ps: Vec<FillVec<r2::P2p>>,
    in_r3bcasts: FillVec<r3::Bcast>,
    in_r3bcasts_fail: FillVec<r3::BcastFail>,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    out_r1bcast: Option<MsgBytes>,
    out_r2bcast: Option<MsgBytes>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r3bcast: Option<MsgBytes>,
    out_r3bcast_fail: Option<MsgBytes>,
    final_output: Option<KeygenOutput>,

    #[cfg(feature = "malicious")]
    behaviour: malicious::Behaviour,
}

// CommonInfo and ShareInfo only used by tofnd. We choose to define them in
// tofn because they contain many types that are either private within tofn's
// scope or belong to crates impored by tofn. To avoid making tofn's structs
// public and importing creates from tofnd, we only expose these structs that
// contain all types we need from tofnd's side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonInfo {
    pub threshold: usize,
    pub ecdsa_public_key: GE,
    pub all_ecdsa_public_key_shares: Vec<GE>,
    pub all_eks: Vec<EncryptionKey>,
    pub all_zkps: Vec<ZkSetup>,
    pub share_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub my_index: usize,
    pub my_dk: DecryptionKey,
    pub my_ek: EncryptionKey,
    pub my_zkp: ZkSetup,
    pub my_ecdsa_secret_key_share: FE,
}

impl Keygen {
    pub fn new(share_count: usize, threshold: usize, my_index: usize) -> Result<Self, ParamsError> {
        validate_params(share_count, threshold, my_index)?;
        Ok(Self {
            status: Status::New,
            share_count,
            threshold,
            my_index,
            r1state: None,
            r2state: None,
            r3state: None,
            in_r1bcasts: FillVec::with_len(share_count),
            in_r2bcasts: FillVec::with_len(share_count),
            in_all_r2p2ps: vec![FillVec::with_len(share_count); share_count],
            in_r3bcasts: FillVec::with_len(share_count),
            in_r3bcasts_fail: FillVec::with_len(share_count),
            out_r1bcast: None,
            out_r2bcast: None,
            out_r2p2ps: None,
            out_r3bcast: None,
            out_r3bcast_fail: None,
            final_output: None,

            #[cfg(feature = "malicious")]
            behaviour: malicious::Behaviour::Honest,
        })
    }
    pub fn clone_output(&self) -> Option<KeygenOutput> {
        self.final_output.clone()
    }
}

pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<crimes::Crime>>>;

// validate_params helper with custom error type
// TODO enforce a maximum share_count?
pub fn validate_params(
    share_count: usize,
    threshold: usize,
    index: usize,
) -> Result<(), ParamsError> {
    if threshold >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, threshold));
    }
    if index >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, index));
    }
    Ok(())
}
#[derive(Debug)]
pub enum ParamsError {
    InvalidThreshold(usize, usize), // (share_count, threshold)
    InvalidIndex(usize, usize),     // (share_count, index)
}

impl std::error::Error for ParamsError {}
impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParamsError::InvalidThreshold(share_count, threshold) => write!(
                f,
                "invalid threshold {} for share_count {}",
                threshold, share_count
            ),
            ParamsError::InvalidIndex(share_count, index) => {
                write!(f, "invalid index {} for share_count {}", index, share_count)
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen
