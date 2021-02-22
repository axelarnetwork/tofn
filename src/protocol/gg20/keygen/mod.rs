use crate::{
    fillvec::FillVec,
    protocol::{MsgBytes, Protocol, ProtocolResult},
};
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
    pub my_ecdsa_secret_key_share: FE,
    pub ecdsa_public_key: GE,
    pub all_eks: Vec<EncryptionKey>,
}

pub mod stateless; // TODO not pub
pub use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use stateless::*;

enum Status {
    New,
    R1,
    R2,
    R3,
    Done,
}

mod protocol;
mod r1;
mod r2;
mod r3;
mod r4;

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p,
    R3Bcast,
}
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}
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
    in_r2p2ps: FillVec<r2::P2p>,
    in_r3bcasts: FillVec<r3::Bcast>,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    out_r1bcast: Option<MsgBytes>,
    out_r2bcast: Option<MsgBytes>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r3bcast: Option<MsgBytes>,
    final_output: Option<SecretKeyShare>,
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
            in_r2p2ps: FillVec::with_len(share_count),
            in_r3bcasts: FillVec::with_len(share_count),
            out_r1bcast: None,
            out_r2bcast: None,
            out_r2p2ps: None,
            out_r3bcast: None,
            final_output: None,
        })
    }
    pub fn get_result(&self) -> Option<&SecretKeyShare> {
        self.final_output.as_ref()
    }
}

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
