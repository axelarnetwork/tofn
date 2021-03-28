use super::keygen::SecretKeyShare;
use serde::{Deserialize, Serialize};

use crate::{fillvec::FillVec, protocol::MsgBytes};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use k256::ecdsa::Asn1Signature;

// TODO isn't there a library for this? Yes. It's called k256.
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
    R2Fail,
    R3,
    R4,
    R5,
    R6,
    R7,
    Done,
    Fail,
}

// all possible crimes
// variant names are of the form <Status><Crime>
// TODO separate Crime enum for each round?
// TODO add variant data (eg. R2ZkpVerify proof from party i to party j fail because x)
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub enum Crime {
//     R2ZkpVerify,
//     R3FailFalseAccusation,
// }
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Culprit {
//     participant_index: usize,
//     crime: Crime,
// }

mod r1;
mod r2;
mod r3;
mod r3fail;
mod r4;
mod r5;
mod r6;
mod r7;
mod r8;

pub struct Sign {
    status: Status,

    // state data
    my_secret_key_share: SecretKeyShare,
    msg_to_sign: FE, // not used until round 7

    // TODO this is a source of bugs
    // "party" indices are in 0..share_count from keygen
    // "participant" indices are in 0..participant_count from sign
    // eg. participant_indices[my_participant_index] == my_secret_key_share.my_index
    // SUGGESTION: use the "newtype" pattern to wrap usize for party vs participant indices
    // https://doc.rust-lang.org/book/ch19-04-advanced-types.html#using-the-newtype-pattern-for-type-safety-and-abstraction
    //   write simple methods to convert between them
    //   eg. my_secret_key_share.all_eks can be indexed only by party indices
    //   eg. in_r2bcasts can be indexed only by participant indices
    participant_indices: Vec<usize>,
    my_participant_index: usize,

    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,
    r4state: Option<r4::State>,
    r5state: Option<r5::State>,
    r6state: Option<r6::State>,
    r7state: Option<r7::State>,

    // incoming messages
    in_r1bcasts: FillVec<r1::Bcast>,
    in_all_r1p2ps: Vec<FillVec<r1::P2p>>, // TODO wasted FillVec for myself
    in_all_r2p2ps: Vec<FillVec<r2::P2p>>,
    in_r3bcasts: FillVec<r3::Bcast>,
    in_r4bcasts: FillVec<r4::Bcast>,
    in_r5bcasts: FillVec<r5::Bcast>,
    in_all_r5p2ps: Vec<FillVec<r5::P2p>>,
    in_r6bcasts: FillVec<r6::Bcast>,
    in_r7bcasts: FillVec<r7::Bcast>,

    in_r2bcasts_fail: FillVec<r2::FailBcast>,

    // TODO currently I do not store my own deserialized output messages
    // instead, my output messages are stored only in serialized form so they can be quickly returned in `get_bcast_out` and `get_p2p_out`
    // if the content of one of my output messages is needed in a future round then it is the responsibility of the round that created that message to copy the needed into into the state for that round
    // example: r3() -> (State, Bcast): `Bcast` contains my `nonce_x_blind_summand`, which is also needed in future rounds
    //   so a copy of nonce_x_blind_summand is stored in `State` as `my_nonce_x_blind_summand`
    // QUESTION: should I instead store all my own deserialized output messages?
    // OPTIONS: (1) store them separately in a `out_` field; (2) store them along with all other parties' messages in `in_` fields

    // outgoing serialized messages
    // initialized to `None`, filled as the protocol progresses
    // p2p Vecs have length participant_indices.len()
    // TODO these fields are used only to implement `Protocol`
    // - delete them and instead serialize on the fly?
    // - move them to a container struct S for `Sign` that's defined in protocol.rs?  But then S implements Protocol instead of Sign...
    out_r1bcast: Option<MsgBytes>,
    out_r1p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r2bcast_fail_serialized: Option<MsgBytes>, // TODO _serialized suffix to distinguish from EXPERIMENT described above
    out_r3bcast: Option<MsgBytes>,
    out_r4bcast: Option<MsgBytes>,
    out_r5bcast: Option<MsgBytes>,
    out_r5p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r6bcast: Option<MsgBytes>,
    out_r7bcast: Option<MsgBytes>,

    final_output: Option<Result<Asn1Signature, Vec<usize>>>, // error type: culprit indices
}

impl Sign {
    pub fn new(
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) -> Result<Self, ParamsError> {
        let my_participant_index = validate_params(my_secret_key_share, participant_indices)?;
        let participant_count = participant_indices.len();
        let msg_to_sign: FE = ECScalar::from(&BigInt::from(msg_to_sign));
        Ok(Self {
            status: Status::New,
            my_secret_key_share: my_secret_key_share.clone(),
            participant_indices: participant_indices.to_vec(),
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
            in_all_r1p2ps: vec![FillVec::with_len(participant_count); participant_count],
            in_all_r2p2ps: vec![FillVec::with_len(participant_count); participant_count],
            in_r3bcasts: FillVec::with_len(participant_count),
            in_r4bcasts: FillVec::with_len(participant_count),
            in_r5bcasts: FillVec::with_len(participant_count),
            in_all_r5p2ps: vec![FillVec::with_len(participant_count); participant_count],
            in_r6bcasts: FillVec::with_len(participant_count),
            in_r7bcasts: FillVec::with_len(participant_count),
            in_r2bcasts_fail: FillVec::with_len(participant_count), // TODO experiment: my own bcast is in here, too
            out_r1bcast: None,
            out_r1p2ps: None,
            out_r2p2ps: None,
            out_r2bcast_fail_serialized: None,
            out_r3bcast: None,
            out_r4bcast: None,
            out_r5bcast: None,
            out_r5p2ps: None,
            out_r6bcast: None,
            out_r7bcast: None,
            final_output: None,
        })
    }
    pub fn get_result(&self) -> Option<Result<&Asn1Signature, &Vec<usize>>> {
        self.final_output.as_ref().map(|o| o.as_ref())
    }
}

/// validate_params helper with custom error type
/// Assume `secret_key_share` is valid and check `participant_indices` against it.
/// Returns my index in participant_indices.
pub fn validate_params(
    secret_key_share: &SecretKeyShare,
    participant_indices: &[usize],
) -> Result<usize, ParamsError> {
    // number of participants must be at least threshold + 1
    let t_plus_1 = secret_key_share.threshold + 1;
    if participant_indices.len() < t_plus_1 {
        return Err(ParamsError::InvalidParticipantCount(
            t_plus_1,
            participant_indices.len(),
        ));
    }

    // check that my index is in the list
    let my_participant_index = participant_indices
        .iter()
        .position(|&i| i == secret_key_share.my_index);
    if my_participant_index.is_none() {
        return Err(ParamsError::ImNotAParticipant(secret_key_share.my_index));
    }

    // check for duplicate party ids
    let mut participant_indices_dedup = participant_indices.to_vec();
    participant_indices_dedup.sort_unstable();
    participant_indices_dedup.dedup();
    if participant_indices_dedup.len() != participant_indices.len() {
        return Err(ParamsError::DuplicateIndices(
            participant_indices.len() - participant_indices_dedup.len(),
        ));
    }

    // check that indices are within range
    // participant_indices_dedup is now sorted and has len > 0, so we need only check the final index
    let max_index = *participant_indices_dedup.last().unwrap();
    if max_index >= secret_key_share.share_count {
        return Err(ParamsError::InvalidParticipantIndex(
            secret_key_share.share_count - 1,
            max_index,
        ));
    }

    Ok(my_participant_index.unwrap())
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

#[cfg(test)]
mod k256_tests;
