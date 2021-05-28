use crate::fillvec::FillVec;
use crate::zkp::paillier::range;

use super::{crimes::Crime, Sign, Status};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::ECPoint,
    GE,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 5

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub r_i: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub k_i_range_proof_wc: range::ProofWc,
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) r: GE,
    pub(super) r_i: GE,
}

pub(super) enum Output {
    Success {
        state: State,
        out_bcast: Bcast,
        out_p2ps: FillVec<P2p>,
    },
    Fail {
        criminals: Vec<Vec<Crime>>,
    },
}

impl Sign {
    pub(super) fn r5(&self) -> Output {
        assert!(matches!(self.status, Status::R4));
        let r1state = self.r1state.as_ref().unwrap();
        let r4state = self.r4state.as_ref().unwrap();

        // curv: verify commits, compute g_gamma
        let mut g_gamma = r1state.g_gamma_i;
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];
        for (i, in_r4bcast) in self.in_r4bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r4bcast = in_r4bcast.as_ref().unwrap();
            let com = HashCommitment::create_commitment_with_user_defined_randomness(
                &in_r4bcast.g_gamma_i.bytes_compressed_to_big_int(),
                &in_r4bcast.g_gamma_i_reveal,
            );
            if self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .g_gamma_i_commit
                != com
            {
                let crime = Crime::R5BadHashCommit;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }
            g_gamma = g_gamma + in_r4bcast.g_gamma_i;
        }

        // k256: verify commits

        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

        let r = g_gamma * r4state.delta_inv; // R
        let r_i = r * r1state.k_i; // R_i from 2020/540

        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let stmt_wc = &range::StatementWc {
            stmt: range::Statement {
                ciphertext: &r1state.encrypted_k_i,
                ek: &self.my_secret_key_share.my_ek,
            },
            msg_g: &r_i,
            g: &r,
        };
        let wit = &range::Witness {
            msg: &r1state.k_i,
            randomness: &r1state.k_i_randomness,
        };
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let k_i_range_proof_wc = other_zkp.range_proof_wc(stmt_wc, wit);
            out_p2ps.insert(i, P2p { k_i_range_proof_wc }).unwrap();
        }

        Output::Success {
            state: State { r, r_i },
            out_bcast: Bcast { r_i },
            out_p2ps,
        }
    }
}
