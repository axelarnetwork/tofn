use super::keygen::SecretKeyShare;
use serde::{Deserialize, Serialize};

use crate::{fillvec::FillVec, protocol::MsgBytes};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
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
    final_output: Option<EcdsaSig>,
}

impl Sign {
    pub fn new(
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: FE,
    ) -> Self {
        // TODO check participant_indices for length and duplicates
        // validate_params(share_count, threshold, my_index).unwrap();
        let participant_count = participant_indices.len();
        let participant_indices = participant_indices.to_vec();
        let my_participant_index = participant_indices
            .iter()
            .position(|&i| i == my_secret_key_share.my_index)
            .unwrap(); // TODO panic
        Self {
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
            final_output: None,
        }
    }
}

#[cfg(test)]
mod tests;
