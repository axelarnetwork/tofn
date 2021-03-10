use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::RangeStatement;
use curv::FE;
use multi_party_ecdsa::utilities::mta;
use serde::{Deserialize, Serialize};

// round 2

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub mta_response_blind: mta::MessageB,
    pub mta_response_keyshare: mta::MessageB,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_mta_blind_summands_rhs: Vec<Option<FE>>,
    pub(super) my_mta_keyshare_summands_rhs: Vec<Option<FE>>,
}

impl Sign {
    pub(super) fn r2(&self) -> (State, Vec<Option<P2p>>) {
        assert!(matches!(self.status, Status::R1));

        // response msg for MtA protocols:
        // 1. my_ecdsa_nonce_summand (other) * my_secret_blind_summand (me)
        // 2. my_ecdsa_nonce_summand (other) * my_secret_key_summand (me)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both

        let r1state = self.r1state.as_ref().unwrap();
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_blind_summands_rhs = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_keyshare_summands_rhs = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // TODO don't use mta!  It sucks!
            // 1. unused return values in MessageB::b()
            // 2. MessageA arg is passed by value
            let other_ek = &self.my_secret_key_share.all_eks[*participant_index];
            let c_a = self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .encrypted_ecdsa_nonce_summand
                .clone();
            self.my_secret_key_share
                .my_zkp
                .verify_range_proof(
                    &RangeStatement {
                        ciphertext: &c_a.c,
                        ek: other_ek,
                    },
                    &self.in_r1p2ps.vec_ref()[i].as_ref().unwrap().range_proof,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "party {} says: range proof failed to verify for party {}",
                        self.my_secret_key_share.my_index, participant_index
                    )
                });

            let (mta_response_blind, my_mta_blind_summand_rhs, _, _) = // (m_b_gamma, beta_gamma)
                mta::MessageB::b(&r1state.my_secret_blind_summand, other_ek, c_a.clone());

            // TODO support MtAwc! https://github.com/axelarnetwork/tofn/issues/7
            let (mta_response_keyshare, my_mta_keyshare_summand_rhs, _, _) = // (m_b_w, beta_wi)
                mta::MessageB::b(&r1state.my_secret_key_summand, other_ek, c_a);

            // TODO I'm not sending my rhs summands even though zengo does https://github.com/axelarnetwork/tofn/issues/7#issuecomment-771379525

            out_p2ps
                .insert(
                    i,
                    P2p {
                        mta_response_blind,
                        mta_response_keyshare,
                    },
                )
                .unwrap();
            my_mta_blind_summands_rhs
                .insert(i, my_mta_blind_summand_rhs)
                .unwrap();
            my_mta_keyshare_summands_rhs
                .insert(i, my_mta_keyshare_summand_rhs)
                .unwrap();
        }

        (
            State {
                my_mta_blind_summands_rhs: my_mta_blind_summands_rhs.into_vec(),
                my_mta_keyshare_summands_rhs: my_mta_keyshare_summands_rhs.into_vec(),
            },
            out_p2ps.into_vec(),
        )
    }
}
