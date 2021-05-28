use crate::fillvec::FillVec;
use crate::zkp::paillier::range;
use crate::{
    hash,
    k256_serde::{self, to_bytes},
    paillier_k256::zk,
};

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
    pub r_i: GE,                               // curv
    pub r_i_k256: k256_serde::ProjectivePoint, // k256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub k_i_range_proof_wc: range::ProofWc,          // curv
    pub k_i_range_proof_wc_k256: zk::range::ProofWc, // k256
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    // curv
    pub(super) r: GE,
    pub(super) r_i: GE,

    // k256
    pub(super) r_k256: k256::ProjectivePoint,
    pub(super) r_i_k256: k256::ProjectivePoint,
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
        let r1bcast = self.in_r1bcasts.vec_ref()[self.my_participant_index]
            .as_ref()
            .unwrap();
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
                    "(curv) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminals[i].push(crime);
            }
            g_gamma = g_gamma + in_r4bcast.g_gamma_i;
        }

        // k256: verify commits
        let criminals_k256: Vec<Vec<Crime>> = self
            .in_r4bcasts
            .vec_ref()
            .iter()
            .enumerate()
            .map(|(i, bcast)| {
                if i == self.my_participant_index {
                    return Vec::new(); // don't verify my own commit
                }
                let bcast = bcast.as_ref().unwrap();
                if hash::commit_with_randomness(
                    to_bytes(bcast.g_gamma_i_k256.unwrap()),
                    &bcast.g_gamma_i_reveal_k256,
                ) != self.in_r1bcasts.vec_ref()[i]
                    .as_ref()
                    .unwrap()
                    .g_gamma_i_commit_k256
                {
                    let crime = Crime::R5BadHashCommit;
                    warn!(
                        "(k256) participant {} detect {:?} by {}",
                        self.my_participant_index, crime, i
                    );
                    vec![crime]
                } else {
                    Vec::new()
                }
            })
            .collect();

        assert_eq!(criminals_k256, criminals);
        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

        // k256: compute g_gamma
        // experiment: use `reduce` instead of `fold`
        let g_gamma_k256 = self
            .in_r4bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().g_gamma_i_k256.unwrap())
            .reduce(|acc, g_gamma_i| acc + g_gamma_i)
            .unwrap();

        // curv
        let r = g_gamma * r4state.delta_inv; // R
        let r_i = r * r1state.k_i; // R_i from 2020/540

        // k256
        let r_k256 = g_gamma_k256 * r4state.delta_inv_k256;
        let r_i_k256 = r_k256 * r1state.k_i_k256;

        // curv: statement and witness
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

        // k256: statement and witness
        let stmt_wc_k256 = &zk::range::StatementWc {
            stmt: zk::range::Statement {
                ciphertext: &r1bcast.k_i_ciphertext_k256,
                ek: self.my_ek_k256(),
            },
            msg_g: &r_i_k256,
            g: &r_k256,
        };
        let wit_k256 = &zk::range::Witness {
            msg: &r1state.k_i_k256,
            randomness: &r1state.k_i_randomness_k256,
        };

        // compute consistency proofs for r_i
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // curv
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let k_i_range_proof_wc = other_zkp.range_proof_wc(stmt_wc, wit);

            // k256
            let other_zkp_k256 = &self.my_secret_key_share.all_zkps_k256[*participant_index];
            let k_i_range_proof_wc_k256 = other_zkp_k256.range_proof_wc(stmt_wc_k256, wit_k256);

            out_p2ps
                .insert(
                    i,
                    P2p {
                        k_i_range_proof_wc,
                        k_i_range_proof_wc_k256,
                    },
                )
                .unwrap();
        }

        Output::Success {
            state: State {
                r,
                r_i,
                r_k256,
                r_i_k256,
            },
            out_bcast: Bcast {
                r_i,
                r_i_k256: r_i_k256.into(),
            },
            out_p2ps,
        }
    }
}
