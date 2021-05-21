use super::{crimes::Crime, Sign, Status};
use crate::zkp::pedersen;
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    // TODO bundle these two fields as a commit-reveal
    pub public_blind_summand: GE,
    pub reveal: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) nonce_x_blind_inv: FE,
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

        // verify proofs and compute nonce_x_blind (delta_i)
        let mut nonce_x_blind = r3state.my_nonce_x_blind_summand;
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        for (i, in_r3bcast) in self.in_r3bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r3bcast = in_r3bcast.as_ref().unwrap();

            pedersen::verify(
                &pedersen::Statement {
                    commit: &in_r3bcast.nonce_x_keyshare_summand_commit,
                },
                &in_r3bcast.nonce_x_keyshare_summand_proof,
            )
            .unwrap_or_else(|e| {
                let crime = Crime::R4BadPedersenProof;
                warn!(
                    "participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });

            nonce_x_blind = nonce_x_blind + in_r3bcast.nonce_x_blind_summand;
        }

        if criminals.iter().map(|v| v.len()).sum::<usize>() == 0 {
            Output::Success {
                state: State {
                    nonce_x_blind_inv: nonce_x_blind.invert(),
                },
                out_bcast: Bcast {
                    public_blind_summand: r1state.g_gamma_i,
                    // TODO hash commitment randomness?
                    reveal: r1state.my_reveal.clone(),
                },
            }
        } else {
            Output::Fail { criminals }
        }
    }
}
