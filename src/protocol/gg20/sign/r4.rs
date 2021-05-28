use super::{crimes::Crime, Sign, Status};
use crate::{
    hash, k256_serde,
    zkp::{pedersen, pedersen_k256},
};
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    // curv
    pub g_gamma_i: GE,
    pub g_gamma_i_reveal: BigInt,

    // k256
    pub g_gamma_i_k256: k256_serde::ProjectivePoint,
    pub g_gamma_i_reveal_k256: hash::Randomness,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) delta_inv: FE,                // curv
    pub(super) delta_inv_k256: k256::Scalar, // k256
}

pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { criminals: Vec<Vec<Crime>> },
}

impl Sign {
    pub(super) fn r4(&self) -> Output {
        assert!(matches!(self.status, Status::R3));
        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();

        // curv: verify proofs, compute delta
        let mut delta = r3state.delta_i;
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];
        for (i, in_r3bcast) in self.in_r3bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r3bcast = in_r3bcast.as_ref().unwrap();

            pedersen::verify(
                &pedersen::Statement {
                    commit: &in_r3bcast.t_i,
                },
                &in_r3bcast.t_i_proof,
            )
            .unwrap_or_else(|e| {
                let crime = Crime::R4BadPedersenProof;
                warn!(
                    "(curv) participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });

            delta = delta + in_r3bcast.delta_i;
        }

        // k256: verify proofs
        let criminals_k256: Vec<Vec<Crime>> = self
            .in_r3bcasts
            .vec_ref()
            .iter()
            .enumerate()
            .map(|(i, bcast)| {
                if i == self.my_participant_index {
                    return Vec::new(); // don't verify my own proof
                }
                let bcast = bcast.as_ref().unwrap();
                if let Err(e) = pedersen_k256::verify(
                    &pedersen_k256::Statement {
                        commit: bcast.t_i_k256.unwrap(),
                    },
                    &bcast.t_i_proof_k256,
                ) {
                    let crime = Crime::R4BadPedersenProof;
                    warn!(
                        "(k256) participant {} detect {:?} by {} because [{}]",
                        self.my_participant_index, crime, i, e
                    );
                    vec![crime]
                } else {
                    Vec::new()
                }
            })
            .collect();

        assert_eq!(criminals_k256, criminals);
        if !criminals.iter().all(|c| c.is_empty()) {
            return Output::Fail { criminals };
        }

        // k256: compute delta_inv
        // experiment: use `reduce` instead of `fold`
        let delta_inv_k256 = self
            .in_r3bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().delta_i_k256.unwrap())
            .reduce(|acc, delta_i| acc + delta_i)
            .unwrap()
            .invert()
            .unwrap();

        Output::Success {
            state: State {
                delta_inv: delta.invert(),
                delta_inv_k256,
            },
            out_bcast: Bcast {
                g_gamma_i: r1state.g_gamma_i,
                g_gamma_i_reveal: r1state.g_gamma_i_reveal.clone(),
                g_gamma_i_k256: r1state.g_gamma_i_k256.into(),
                g_gamma_i_reveal_k256: r1state.g_gamma_i_reveal_k256.clone(),
            },
        }
    }
}
