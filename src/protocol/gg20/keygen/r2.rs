use curv::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};

use super::{Keygen, Status};
use crate::{fillvec::FillVec, protocol::gg20::vss};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_reveal: BigInt,
    pub u_i_share_commitments: Vec<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub u_i_share: FE, // threshold share of my_ecdsa_secret_summand
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

        let (my_u_i_share_commitments, my_u_i_shares) =
            vss::share(self.threshold, self.share_count, &r1state.my_u_i);
        assert_eq!(my_u_i_share_commitments[0], r1state.my_y_i);

        let mut out_p2ps = FillVec::with_len(self.share_count);
        let my_share_of_my_u_i = my_u_i_shares[self.my_index].clone();
        for (i, my_u_i_share) in my_u_i_shares.into_iter().enumerate() {
            if i == self.my_index {
                continue;
            }
            out_p2ps
                .insert(
                    i,
                    P2p {
                        u_i_share: my_u_i_share,
                    },
                )
                .unwrap();
        }

        // TODO sign and encrypt each p2p_msg

        let out_bcast = Bcast {
            y_i_reveal: r1state.my_y_i_reveal.clone(),
            u_i_share_commitments: my_u_i_share_commitments.clone(),
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
