use super::{crimes::Crime, Sign, Status};
use crate::fillvec::FillVec;
use crate::{
    hash,
    k256_serde::{self, to_bytes},
    paillier_k256::zk,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 5

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub R_i_k256: k256_serde::ProjectivePoint, // k256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub k_i_range_proof_wc_k256: zk::range::ProofWc, // k256
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
#[allow(non_snake_case)]
pub(super) struct State {
    pub(super) R_k256: k256::ProjectivePoint,
    pub(super) R_i_k256: k256::ProjectivePoint,
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
    #[allow(non_snake_case)]
    pub(super) fn r5(&self) -> Output {
        assert!(matches!(self.status, Status::R4));
        let r1state = self.r1state.as_ref().unwrap();
        let r1bcast = self.in_r1bcasts.vec_ref()[self.my_participant_index]
            .as_ref()
            .unwrap();
        let r4state = self.r4state.as_ref().unwrap();

        // k256: verify commits
        let criminals: Vec<Vec<Crime>> = self
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
                    to_bytes(bcast.Gamma_i_k256.unwrap()),
                    &bcast.Gamma_i_reveal_k256,
                ) != self.in_r1bcasts.vec_ref()[i]
                    .as_ref()
                    .unwrap()
                    .Gamma_i_commit_k256
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
        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

        // k256: compute Gamma
        // experiment: use `reduce` instead of `fold`
        let Gamma_k256 = self
            .in_r4bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().Gamma_i_k256.unwrap())
            .reduce(|acc, Gamma_i| acc + Gamma_i)
            .unwrap();

        // k256
        let R_k256 = Gamma_k256 * r4state.delta_inv_k256;
        let R_i_k256 = R_k256 * r1state.k_i_k256;

        // k256: statement and witness
        let stmt_wc_k256 = &zk::range::StatementWc {
            stmt: zk::range::Statement {
                ciphertext: &r1bcast.k_i_ciphertext_k256,
                ek: self.my_ek_k256(),
            },
            msg_g: &R_i_k256,
            g: &R_k256,
        };
        let wit_k256 = &zk::range::Witness {
            msg: &r1state.k_i_k256,
            randomness: &r1state.k_i_randomness_k256,
        };

        // compute consistency proofs for R_i
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.share.my_index {
                continue;
            }

            // k256
            let other_zkp_k256 = &self.my_secret_key_share.group.all_zkps_k256[*participant_index];
            let k_i_range_proof_wc_k256 = other_zkp_k256.range_proof_wc(stmt_wc_k256, wit_k256);

            out_p2ps
                .insert(
                    i,
                    P2p {
                        k_i_range_proof_wc_k256,
                    },
                )
                .unwrap();
        }

        Output::Success {
            state: State { R_k256, R_i_k256 },
            out_bcast: Bcast {
                R_i_k256: R_i_k256.into(),
            },
            out_p2ps,
        }
    }
}
