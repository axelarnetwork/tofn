use curv::{elliptic::curves::traits::ECScalar, BigInt, FE, GE};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};

use super::{Keygen, Status};
use crate::{
    fillvec::FillVec,
    hash, k256_serde,
    protocol::gg20::{vss, vss_k256},
};

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, tracing::info};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_reveal: BigInt,
    pub(super) u_i_share_commitments: Vec<GE>,

    pub(super) y_i_reveal_k256: hash::Randomness,
    pub(super) u_i_share_commits_k256: Vec<k256_serde::AffinePoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub encrypted_u_i_share: BigInt, // threshold share of my_ecdsa_secret_summand
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_share_of_my_u_i: FE,
    pub(super) my_u_i_share_commitments: Vec<GE>,
}

impl Keygen {
    pub(super) fn r2(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::R1));
        let r1state = self.r1state.as_ref().unwrap();

        // TODO Paillier, delete this for loop
        for (i, in_r1bcast) in self.in_r1bcasts.vec_ref().iter().enumerate() {
            if i == self.my_index {
                continue;
            }
            let r1bcast = in_r1bcast.as_ref().unwrap();
            r1bcast
                .correct_key_proof
                .verify(&r1bcast.ek)
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: key proof failed to verify for party {}",
                        self.my_index, i
                    )
                });
            if !r1bcast.zkp.verify_composite_dlog_proof() {
                panic!(
                    "party {} says: dlog proof failed to verify for party {}",
                    self.my_index, i
                );
            }
        }

        let (my_u_i_share_commits_k256, my_u_i_shares_k256) =
            vss_k256::share(self.threshold, self.share_count, &r1state.my_u_i_k256);
        assert_eq!(my_u_i_share_commits_k256[0], r1state.my_y_i_k256);

        let (my_u_i_share_commitments, my_u_i_shares) =
            vss::share(self.threshold, self.share_count, &r1state.my_u_i);

        #[cfg(feature = "malicious")]
        let my_u_i_shares = if let Behaviour::R2BadShare { victim } = self.behaviour {
            info!("malicious party {} do {:?}", self.my_index, self.behaviour);
            my_u_i_shares
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if i == victim {
                        let one: FE = ECScalar::from(&BigInt::one());
                        *s + one
                    } else {
                        *s
                    }
                })
                .collect()
        } else {
            my_u_i_shares
        };

        assert_eq!(my_u_i_share_commitments[0], r1state.my_y_i);

        let mut out_p2ps = FillVec::with_len(self.share_count);
        let my_share_of_my_u_i = my_u_i_shares[self.my_index];
        for (i, my_u_i_share) in my_u_i_shares.into_iter().enumerate() {
            if i == self.my_index {
                continue;
            }

            // encrypt the share for party i
            let ek = &self.in_r1bcasts.vec_ref()[i].as_ref().unwrap().ek;
            let randomness = Randomness::sample(ek);
            let encrypted_u_i_share = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(my_u_i_share.to_big_int()),
                &randomness,
            )
            .0
            .into_owned();

            #[cfg(feature = "malicious")]
            let encrypted_u_i_share = match self.behaviour {
                Behaviour::R2BadEncryption { victim } if victim == i => {
                    info!("malicious party {} do {:?}", self.my_index, self.behaviour);
                    encrypted_u_i_share + BigInt::one()
                }
                _ => encrypted_u_i_share,
            };

            out_p2ps
                .insert(
                    i,
                    P2p {
                        encrypted_u_i_share,
                    },
                )
                .unwrap();
        }

        let out_bcast = Bcast {
            y_i_reveal: r1state.my_y_i_reveal.clone(),
            u_i_share_commitments: my_u_i_share_commitments.clone(),
            y_i_reveal_k256: r1state.my_y_i_reveal_k256.clone(),
            u_i_share_commits_k256: my_u_i_share_commits_k256
                .into_iter()
                .map(|c| k256_serde::AffinePoint(c))
                .collect(),
        };
        (
            State {
                my_share_of_my_u_i,
                my_u_i_share_commitments,
            },
            out_bcast,
            out_p2ps,
        )
    }
}
