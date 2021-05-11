use super::{crimes::Crime, Keygen, Status};
use crate::protocol::gg20::vss;
use curv::{
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::{DLogProof, ProveDLog},
    },
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use paillier::{Open, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, curv::elliptic::curves::traits::ECScalar, tracing::info};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub dlog_proof: DLogProof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) ecdsa_public_key: GE,                 // the final pub key
    pub(super) my_ecdsa_secret_key_share: FE,        // my final secret key share
    pub(super) all_ecdsa_public_key_shares: Vec<GE>, // these sum to ecdsa_public_key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastFail {
    pub vss_failures: Vec<Complaint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Complaint {
    pub criminal_index: usize,
    pub vss_share: FE,
    // TODO encryption randomness
}

pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { criminals: Vec<Vec<Crime>> },
    FailVss { out_bcast: BcastFail },
}

impl Keygen {
    pub(super) fn r3(&self) -> Output {
        assert!(matches!(self.status, Status::R2));
        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();

        let mut criminals = vec![Vec::new(); self.share_count];
        let mut vss_failures = Vec::new();

        // check commitments
        // compute my_ecdsa_secret_key_share, ecdsa_public_key, all_ecdsa_public_key_shares
        let mut ecdsa_public_key = r1state.my_y_i;
        let mut my_ecdsa_secret_key_share = r2state.my_share_of_my_u_i;
        let mut all_ecdsa_public_key_shares: Vec<GE> = (0..self.share_count)
            // start each summation with my contribution
            .map(|i| vss::get_point_commitment(&r2state.my_u_i_share_commitments, i))
            .collect();

        #[allow(clippy::needless_range_loop)]
        for i in 0..self.share_count {
            if i == self.my_index {
                continue;
            }
            let r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();
            let r2bcast = self.in_r2bcasts.vec_ref()[i].as_ref().unwrap();
            let my_r2p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_index]
                .as_ref()
                .unwrap();
            let y_i = &r2bcast.u_i_share_commitments[0];
            let y_i_commit = HashCommitment::create_commitment_with_user_defined_randomness(
                &y_i.bytes_compressed_to_big_int(),
                &r2bcast.y_i_reveal,
            );

            if y_i_commit != r1bcast.y_i_commit {
                let crime = Crime::R3BadReveal;
                warn!("party {} detect {:?} by {}", self.my_index, crime, i);
                criminals[i].push(crime);
            }

            // decrypt share
            let (u_i_share_plaintext, u_i_share_randomness) = Paillier::open(
                &self.r1state.as_ref().unwrap().my_dk,
                &RawCiphertext::from(&my_r2p2p.encrypted_u_i_share),
            );
            let u_i_share: FE = ECScalar::from(&u_i_share_plaintext.0);

            let vss_valid =
                vss::validate_share(&r2bcast.u_i_share_commitments, &u_i_share, self.my_index)
                    .is_ok();

            #[cfg(feature = "malicious")]
            let vss_valid = match self.behaviour {
                Behaviour::R3FalseAccusation { victim } if victim == i && vss_valid => {
                    info!("malicious party {} do {:?}", self.my_index, self.behaviour);
                    false
                }
                _ => vss_valid,
            };

            if !vss_valid {
                warn!(
                    "party {} accuse {} of {:?}",
                    self.my_index,
                    i,
                    Crime::R4FailBadVss {
                        victim: self.my_index
                    },
                );
                vss_failures.push(Complaint {
                    criminal_index: i,
                    vss_share: u_i_share, // TODO (plaintext, randomness)
                });
            }

            ecdsa_public_key = ecdsa_public_key + y_i;
            my_ecdsa_secret_key_share = my_ecdsa_secret_key_share + u_i_share;

            for (j, ecdsa_public_key_share) in all_ecdsa_public_key_shares.iter_mut().enumerate() {
                *ecdsa_public_key_share = *ecdsa_public_key_share
                    + vss::get_point_commitment(&r2bcast.u_i_share_commitments, j);
            }
        }

        #[cfg(feature = "malicious")]
        match self.behaviour {
            Behaviour::R3FalseAccusation { victim } if victim == self.my_index => {
                info!(
                    "malicious party {} do {:?} (self accusation)",
                    self.my_index, self.behaviour
                );
                vss_failures.push(Complaint {
                    criminal_index: self.my_index,
                    vss_share: FE::new_random(), // doesn't matter what we put here
                });
            }
            _ => (),
        };

        // prioritize commit faiure path over vss failure path
        if !criminals.iter().all(|c| c.is_empty()) {
            return Output::Fail { criminals };
        }
        if !vss_failures.is_empty() {
            return Output::FailVss {
                out_bcast: BcastFail { vss_failures },
            };
        }

        all_ecdsa_public_key_shares[self.my_index] = GE::generator() * my_ecdsa_secret_key_share;

        Output::Success {
            state: State {
                ecdsa_public_key,
                my_ecdsa_secret_key_share,
                all_ecdsa_public_key_shares,
            },
            out_bcast: Bcast {
                dlog_proof: DLogProof::prove(&my_ecdsa_secret_key_share),
            },
        }
    }
}
