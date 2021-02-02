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
    Done,
}

mod r1;
mod r2;
mod r3;

pub struct Sign {
    status: Status,

    // state data
    my_secret_key_share: SecretKeyShare,
    participant_indices: Vec<usize>,
    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    // p2p Vecs have length participant_indices.len()
    in_r1bcasts: FillVec<r1::Bcast>,
    in_r1p2ps: FillVec<r1::P2p>,
    in_r2p2ps: FillVec<r2::P2p>,
    in_r3bcasts: FillVec<r3::Bcast>,
    // out_r1bcast: Option<MsgBytes>,
    // out_r1p2ps: Option<Vec<Option<MsgBytes>>>,
}

impl Sign {
    pub fn new(my_secret_key_share: &SecretKeyShare, participant_indices: &[usize]) -> Self {
        // TODO check participant_indices for length and duplicates
        // validate_params(share_count, threshold, my_index).unwrap();
        Self {
            status: Status::New,
            my_secret_key_share: my_secret_key_share.clone(),
            participant_indices: participant_indices.to_vec(),
            r1state: None,
            r2state: None,
            r3state: None,
            in_r1bcasts: FillVec::with_capacity(participant_indices.len()),
            in_r1p2ps: FillVec::with_capacity(participant_indices.len()),
            in_r2p2ps: FillVec::with_capacity(participant_indices.len()),
            in_r3bcasts: FillVec::with_capacity(participant_indices.len()),
        }
    }
}

#[cfg(test)]
mod tests;
