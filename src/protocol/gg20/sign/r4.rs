use super::{crimes::Crime, Sign, Status};
use crate::zkp::pedersen;
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub g_gamma_i: GE,
    pub g_gamma_i_reveal: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) delta_inv: FE,
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
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // verify proofs and compute nonce_x_blind (delta_i)
        let mut delta = r3state.delta_i;
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
                    "participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });

            delta = delta + in_r3bcast.delta_i;
        }

        if criminals.iter().map(|v| v.len()).sum::<usize>() == 0 {
            Output::Success {
                state: State {
                    delta_inv: delta.invert(),
                },
                out_bcast: Bcast {
                    g_gamma_i: r1state.g_gamma_i,
                    g_gamma_i_reveal: r1state.g_gamma_i_reveal.clone(),
                },
            }
        } else {
            Output::Fail { criminals }
        }
    }
}
