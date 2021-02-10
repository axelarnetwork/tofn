use super::keygen::SecretKeyShare;
use serde::{Deserialize, Serialize};

use crate::{fillvec::FillVec, protocol::MsgBytes};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};

// TODO isn't there a library for this?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaSig {
    pub r: FE,
    pub s: FE,
}
impl EcdsaSig {
    pub fn verify(&self, pubkey: &GE, msg: &FE) -> bool {
        let s_inv = self.s.invert();
        let randomizer = GE::generator() * (*msg * s_inv) + *pubkey * (self.r * s_inv);
        self.r == ECScalar::from(&randomizer.x_coor().unwrap().mod_floor(&FE::q()))
    }
}

mod protocol;

enum Status {
    New,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    Done,
}

mod r1;
mod r2;
mod r3;
mod r4;
mod r5;
mod r6;
mod r7;
mod r8;

pub struct Sign {
    status: Status,

    // state data
    my_secret_key_share: SecretKeyShare,
    participant_indices: Vec<usize>,
    msg_to_sign: FE,             // not used until round 7
    my_participant_index: usize, // participant_indices[my_participant_index] == my_secret_key_share.my_index
    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,
    r4state: Option<r4::State>,
    r5state: Option<r5::State>,
    r6state: Option<r6::State>,
    r7state: Option<r7::State>,

    // incoming messages
    in_r1bcasts: FillVec<r1::Bcast>,
    in_r1p2ps: FillVec<r1::P2p>,
    in_r2p2ps: FillVec<r2::P2p>,
    in_r3bcasts: FillVec<r3::Bcast>,
    in_r4bcasts: FillVec<r4::Bcast>,
    in_r5bcasts: FillVec<r5::Bcast>,
    in_r6bcasts: FillVec<r6::Bcast>,
    in_r7bcasts: FillVec<r7::Bcast>,

    // outgoing messages
    // initialized to `None`, filled as the protocol progresses
    // p2p Vecs have length participant_indices.len()
    out_r1bcast: Option<MsgBytes>,
    out_r1p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r3bcast: Option<MsgBytes>,
    out_r4bcast: Option<MsgBytes>,
    out_r5bcast: Option<MsgBytes>,
    out_r6bcast: Option<MsgBytes>,
    out_r7bcast: Option<MsgBytes>,
    final_output: Option<EcdsaSig>,
}

impl Sign {
    pub fn new(
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) -> Result<Self, ParamsError> {
        let (participant_indices, my_participant_index) =
            validate_params(my_secret_key_share, participant_indices)?;
        let participant_count = participant_indices.len();
        let msg_to_sign: FE = ECScalar::from(&BigInt::from(msg_to_sign));
        Ok(Self {
            status: Status::New,
            my_secret_key_share: my_secret_key_share.clone(),
            participant_indices,
            my_participant_index,
            msg_to_sign,
            r1state: None,
            r2state: None,
            r3state: None,
            r4state: None,
            r5state: None,
            r6state: None,
            r7state: None,
            in_r1bcasts: FillVec::with_len(participant_count),
            in_r1p2ps: FillVec::with_len(participant_count),
            in_r2p2ps: FillVec::with_len(participant_count),
            in_r3bcasts: FillVec::with_len(participant_count),
            in_r4bcasts: FillVec::with_len(participant_count),
            in_r5bcasts: FillVec::with_len(participant_count),
            in_r6bcasts: FillVec::with_len(participant_count),
            in_r7bcasts: FillVec::with_len(participant_count),
            out_r1bcast: None,
            out_r1p2ps: None,
            out_r2p2ps: None,
            out_r3bcast: None,
            out_r4bcast: None,
            out_r5bcast: None,
            out_r6bcast: None,
            out_r7bcast: None,
            final_output: None,
        })
    }
    pub fn get_result(&self) -> Option<&EcdsaSig> {
        self.final_output.as_ref()
    }
}

/// validate_params helper with custom error type
/// Assume `secret_key_share` is valid and check `participant_indices` against it.
/// Returns sorted `participant_indices` and my participant index in that list.
pub fn validate_params(
    secret_key_share: &SecretKeyShare,
    participant_indices: &[usize],
) -> Result<(Vec<usize>, usize), ParamsError> {
    // participant count must be exactly threshold + 1
    let t_plus_1 = secret_key_share.threshold + 1;
    if participant_indices.len() != t_plus_1 {
        return Err(ParamsError::InvalidParticipantCount(
            t_plus_1,
            participant_indices.len(),
        ));
    }

    // check for duplicate party ids
    let old_len = participant_indices.len();
    let mut participant_indices = participant_indices.to_vec();
    participant_indices.sort_unstable();
    participant_indices.dedup();
    if participant_indices.len() != old_len {
        return Err(ParamsError::DuplicateIndices(
            old_len - participant_indices.len(),
        ));
    }

    // check that indices are within range
    // participant_indices is now sorted and has len > 0, so we need only check the final index
    let max_index = *participant_indices.last().unwrap();
    if max_index >= secret_key_share.share_count {
        return Err(ParamsError::InvalidParticipantIndex(
            secret_key_share.share_count - 1,
            max_index,
        ));
    }

    // check that my index is in the list
    let my_participant_index = participant_indices
        .iter()
        .position(|&i| i == secret_key_share.my_index);
    if my_participant_index.is_none() {
        return Err(ParamsError::ImNotAParticipant(secret_key_share.my_index));
    }

    Ok((participant_indices, my_participant_index.unwrap()))
}

#[derive(Debug)]
pub enum ParamsError {
    DuplicateIndices(usize),               // dup_count
    InvalidParticipantCount(usize, usize), // (expect, actual)
    InvalidParticipantIndex(usize, usize), // (max, invalid_index)
    ImNotAParticipant(usize),              // my_index
}

impl std::error::Error for ParamsError {}
impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParamsError::DuplicateIndices(dup_count) => {
                write!(f, "{} duplicate participant indices detected", dup_count)
            }
            ParamsError::InvalidParticipantCount(expect, actual) => {
                write!(
                    f,
                    "invalid participant count: expect: {}, actual: {}",
                    expect, actual
                )
            }
            ParamsError::InvalidParticipantIndex(max, invalid_index) => {
                write!(
                    f,
                    "invalid participant index: max: {}, found: {}",
                    max, invalid_index
                )
            }
            ParamsError::ImNotAParticipant(my_index) => {
                write!(f, "my_index {} not found in participant_indices", my_index)
            }
        }
    }
}

#[cfg(test)]
mod tests;
