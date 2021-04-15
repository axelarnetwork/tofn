use crate::fillvec::FillVec;
use crate::zkp::range;

use super::{Sign, Status};
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
    pub ecdsa_randomizer_x_nonce_summand: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub ecdsa_randomizer_x_nonce_summand_proof: range::ProofWc,
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) ecdsa_randomizer: GE,
    pub(super) my_ecdsa_randomizer_x_nonce_summand: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Culprit {
    pub participant_index: usize,
    pub crime: Crime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Crime {
    CommitReveal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailBcast {
    pub culprits: Vec<Culprit>,
}
pub enum Output {
    Success {
        state: State,
        out_bcast: Bcast,
        out_p2ps: FillVec<P2p>,
    },
    Fail {
        out_bcast: FailBcast,
    },
}

impl Sign {
    pub(super) fn r5(&self) -> Output {
        assert!(matches!(self.status, Status::R4));
        let r1state = self.r1state.as_ref().unwrap();
        let r4state = self.r4state.as_ref().unwrap();

        // compute R (aka ecdsa_randomizer) as per phase 4 of 2020/540
        // first verify all commits and compute sum of all reveals
        let mut public_blind = r1state.my_public_blind_summand;
        let mut culprits = Vec::new();

        for (i, in_r4bcast) in self.in_r4bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r4bcast = in_r4bcast.as_ref().unwrap();
            let com = HashCommitment::create_commitment_with_user_defined_randomness(
                &in_r4bcast
                    .public_blind_summand
                    .bytes_compressed_to_big_int(),
                &in_r4bcast.reveal,
            );
            if self.in_r1bcasts.vec_ref()[i].as_ref().unwrap().commit != com {
                warn!(
                    "party {} says: commit failed to verify for party {}",
                    self.my_secret_key_share.my_index, self.participant_indices[i]
                );
                culprits.push(Culprit {
                    participant_index: i,
                    crime: Crime::CommitReveal,
                });
            }
            public_blind = public_blind + in_r4bcast.public_blind_summand;
        }

        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: FailBcast { culprits },
            };
        }

        let ecdsa_randomizer = public_blind * r4state.nonce_x_blind_inv; // R
        let my_ecdsa_randomizer_x_nonce_summand = ecdsa_randomizer * r1state.my_ecdsa_nonce_summand; // R_i from 2020/540

        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let stmt_wc = &range::StatementWc {
            stmt: range::Statement {
                ciphertext: &r1state.my_encrypted_ecdsa_nonce_summand,
                ek: &self.my_secret_key_share.my_ek,
            },
            msg_g: &my_ecdsa_randomizer_x_nonce_summand,
            g: &ecdsa_randomizer,
        };
        let wit = &range::Witness {
            msg: &r1state.my_ecdsa_nonce_summand,
            randomness: &r1state.my_encrypted_ecdsa_nonce_summand_randomness,
        };
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let range_proof_wc = other_zkp.range_proof_wc(stmt_wc, wit);
            out_p2ps
                .insert(
                    i,
                    P2p {
                        ecdsa_randomizer_x_nonce_summand_proof: range_proof_wc,
                    },
                )
                .unwrap();
        }

        Output::Success {
            state: State {
                ecdsa_randomizer,
                my_ecdsa_randomizer_x_nonce_summand,
            },
            out_bcast: Bcast {
                ecdsa_randomizer_x_nonce_summand: my_ecdsa_randomizer_x_nonce_summand,
            },
            out_p2ps,
        }
    }
}
