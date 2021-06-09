use super::{crimes::Crime, Sign, Status};
use crate::{hash, k256_serde, zkp::pedersen_k256};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i_k256: k256_serde::ProjectivePoint,
    pub Gamma_i_reveal_k256: hash::Randomness,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
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

        // verify proofs
        let criminals: Vec<Vec<Crime>> = self
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
                        commit: bcast.T_i_k256.unwrap(),
                    },
                    &bcast.T_i_proof_k256,
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
        if !criminals.iter().all(Vec::is_empty) {
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
            state: State { delta_inv_k256 },
            out_bcast: Bcast {
                Gamma_i_k256: r1state.Gamma_i_k256.into(),
                Gamma_i_reveal_k256: r1state.Gamma_i_reveal_k256.clone(),
            },
        }
    }
}
