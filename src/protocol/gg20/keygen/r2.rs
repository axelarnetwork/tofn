use curv::{BigInt, FE, GE};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};

use super::{Keygen, Status};
use crate::protocol::gg20::vss;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub reveal: BigInt,
    pub secret_share_commitments: Vec<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub ecdsa_secret_summand_share: FE, // threshold share of my_ecdsa_secret_summand
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_share_of_my_ecdsa_secret_summand: FE,
    pub(super) all_commits: Vec<BigInt>,
    pub(super) all_eks: Vec<EncryptionKey>,
}

impl Keygen {
    pub(super) fn r2(&self) -> (State, Bcast, Vec<Option<P2p>>) {
        assert!(matches!(self.status, Status::R1));
        let r1state = self.r1state.as_ref().unwrap();

        // verify other parties' proofs and build commits list
        let mut all_commits = Vec::with_capacity(self.share_count);
        let mut all_eks = Vec::with_capacity(self.share_count);
        for (i, bcast) in self.in_r1bcasts.vec_ref().iter().enumerate() {
            if i == self.my_index {
                all_commits.push(r1state.my_commit.clone());
                all_eks.push(r1state.my_ek.clone());
                continue; // don't verify my own proof
            }
            let bcast = bcast.clone().unwrap_or_else(|| {
                panic!(
                    "party {} says: missing input for party {}",
                    self.my_index, i
                )
            });
            bcast
                .correct_key_proof
                .verify(&bcast.ek)
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: key proof failed to verify for party {}",
                        self.my_index, i
                    )
                });
            bcast
                .zkp
                .dlog_proof
                .verify(&bcast.zkp.dlog_statement)
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: dlog proof failed to verify for party {}",
                        self.my_index, i
                    )
                });
            all_commits.push(bcast.commit);
            all_eks.push(bcast.ek);
        }
        assert_eq!(all_commits.len(), self.share_count);
        assert_eq!(all_eks.len(), self.share_count);

        let (secret_share_commitments, ecdsa_secret_summand_shares) = vss::share(
            self.threshold,
            self.share_count,
            &r1state.my_ecdsa_secret_summand,
        );
        assert_eq!(secret_share_commitments[0], r1state.my_ecdsa_public_summand);

        // prepare outgoing p2p messages: secret shares of my_ecdsa_secret_summand
        let mut out_p2p: Vec<Option<P2p>> = ecdsa_secret_summand_shares
            .into_iter()
            .map(|x| {
                Some(P2p {
                    ecdsa_secret_summand_share: x,
                })
            })
            .collect();
        let my_share_of_my_ecdsa_secret_summand = out_p2p[self.my_index]
            .take()
            .unwrap()
            .ecdsa_secret_summand_share;

        // TODO sign and encrypt each p2p_msg
        assert_eq!(out_p2p.len(), self.share_count);

        let out_bcast = Bcast {
            reveal: r1state.my_reveal.clone(),
            secret_share_commitments,
        };
        (
            State {
                my_share_of_my_ecdsa_secret_summand,
                all_commits,
                all_eks,
            },
            out_bcast,
            out_p2p,
        )
    }
}
