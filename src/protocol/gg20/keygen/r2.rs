use curv::{BigInt, FE, GE};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};

use super::{Keygen, Status};
use crate::{fillvec::FillVec, protocol::gg20::vss, zkp::paillier2::ZkSetup};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub reveal: BigInt,
    pub secret_summand_share_commitments: Vec<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub secret_summand_share: FE, // threshold share of my_ecdsa_secret_summand
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_share_of_my_ecdsa_secret_summand: FE,
    pub(super) my_secret_summand_share_commitments: Vec<GE>,
    pub(super) all_commits: Vec<BigInt>,
    pub(super) all_eks: Vec<EncryptionKey>,
    pub(super) all_zkps: Vec<ZkSetup>,
}

impl Keygen {
    pub(super) fn r2(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::R1));
        let r1state = self.r1state.as_ref().unwrap();

        // verify other parties' proofs and build commits list
        let mut all_commits = Vec::with_capacity(self.share_count);
        let mut all_eks = Vec::with_capacity(self.share_count);
        let mut all_zkps = Vec::with_capacity(self.share_count);
        for (i, in_r1bcast) in self.in_r1bcasts.vec_ref().iter().enumerate() {
            if i == self.my_index {
                all_commits.push(r1state.my_commit.clone());
                all_eks.push(r1state.my_ek.clone());
                all_zkps.push(r1state.my_zkp.clone());
                continue; // don't verify my own proof
            }
            let in_r1bcast = in_r1bcast.as_ref().unwrap_or_else(|| {
                panic!(
                    "party {} says: missing input for party {}",
                    self.my_index, i
                )
            });
            in_r1bcast
                .correct_key_proof
                .verify(&in_r1bcast.ek)
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: key proof failed to verify for party {}",
                        self.my_index, i
                    )
                });
            in_r1bcast
                .zkp
                .dlog_proof
                .verify(&in_r1bcast.zkp.dlog_statement)
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: dlog proof failed to verify for party {}",
                        self.my_index, i
                    )
                });
            all_commits.push(in_r1bcast.commit.clone());
            all_eks.push(in_r1bcast.ek.clone());
            all_zkps.push(in_r1bcast.zkp.clone());
        }
        assert_eq!(all_commits.len(), self.share_count);
        assert_eq!(all_eks.len(), self.share_count);
        assert_eq!(all_zkps.len(), self.share_count);

        let (my_secret_summand_share_commitments, my_secret_summand_shares) = vss::share(
            self.threshold,
            self.share_count,
            &r1state.my_ecdsa_secret_summand,
        );
        assert_eq!(
            my_secret_summand_share_commitments[0],
            r1state.my_ecdsa_public_summand
        );

        // prepare outgoing p2p messages: secret shares of my_ecdsa_secret_summand
        let mut out_p2ps = FillVec::with_len(self.share_count);
        let mut my_share_of_my_ecdsa_secret_summand = None;
        for (i, secret_summand_share) in my_secret_summand_shares.into_iter().enumerate() {
            if i == self.my_index {
                my_share_of_my_ecdsa_secret_summand = Some(secret_summand_share);
                continue;
            }
            out_p2ps
                .insert(
                    i,
                    P2p {
                        secret_summand_share,
                    },
                )
                .unwrap();
        }

        // TODO sign and encrypt each p2p_msg

        let out_bcast = Bcast {
            reveal: r1state.my_reveal.clone(),
            secret_summand_share_commitments: my_secret_summand_share_commitments.clone(),
        };
        (
            State {
                my_share_of_my_ecdsa_secret_summand: my_share_of_my_ecdsa_secret_summand.unwrap(),
                my_secret_summand_share_commitments,
                all_commits,
                all_eks,
                all_zkps,
            },
            out_bcast,
            out_p2ps,
        )
    }
}
