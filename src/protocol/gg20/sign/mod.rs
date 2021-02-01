use super::keygen::SecretKeyShare;
use serde::{Deserialize, Serialize};

use crate::protocol::gg20::vss;
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

pub struct Sign {
    status: Status,

    // init data
    my_secret_key_share: SecretKeyShare,
    participant_indices: Vec<usize>,
    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    // p2p Vecs have length participant_indices.len()
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
        }
    }
}

#[cfg(test)]
mod tests;
