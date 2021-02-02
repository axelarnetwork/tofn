use super::keygen::SecretKeyShare;
use serde::{Deserialize, Serialize};

use crate::fillvec::FillVec;
use curv::{
    arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

enum Status {
    New,
    R1,
    R2,
    R3,
    R4,
    R5,
    Done,
}

mod r1;
mod r2;
mod r3;
mod r4;
mod r5;

pub struct Sign {
    status: Status,

    // state data
    my_secret_key_share: SecretKeyShare,
    participant_indices: Vec<usize>,
    my_participant_index: usize, // participant_indices[my_participant_index] == my_secret_key_share.my_index
    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,
    r4state: Option<r4::State>,
    r5state: Option<r5::State>,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    // p2p Vecs have length participant_indices.len()
    in_r1bcasts: FillVec<r1::Bcast>,
    in_r1p2ps: FillVec<r1::P2p>,
    in_r2p2ps: FillVec<r2::P2p>,
    in_r3bcasts: FillVec<r3::Bcast>,
    in_r4bcasts: FillVec<r4::Bcast>,
    in_r5bcasts: FillVec<r5::Bcast>,
    // out_r1bcast: Option<MsgBytes>,
    // out_r1p2ps: Option<Vec<Option<MsgBytes>>>,
}

impl Sign {
    pub fn new(my_secret_key_share: &SecretKeyShare, participant_indices: &[usize]) -> Self {
        // TODO check participant_indices for length and duplicates
        // validate_params(share_count, threshold, my_index).unwrap();
        let participant_indices = participant_indices.to_vec();
        let my_participant_index = *participant_indices
            .iter()
            .find(|&&i| i == my_secret_key_share.my_index)
            .unwrap();
        Self {
            status: Status::New,
            my_secret_key_share: my_secret_key_share.clone(),
            my_participant_index,
            r1state: None,
            r2state: None,
            r3state: None,
            r4state: None,
            r5state: None,
            in_r1bcasts: FillVec::with_capacity(participant_indices.len()),
            in_r1p2ps: FillVec::with_capacity(participant_indices.len()),
            in_r2p2ps: FillVec::with_capacity(participant_indices.len()),
            in_r3bcasts: FillVec::with_capacity(participant_indices.len()),
            in_r4bcasts: FillVec::with_capacity(participant_indices.len()),
            in_r5bcasts: FillVec::with_capacity(participant_indices.len()),
            participant_indices,
        }
    }
}

#[cfg(test)]
mod tests;
