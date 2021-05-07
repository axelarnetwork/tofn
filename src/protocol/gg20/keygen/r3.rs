use super::{crimes::Crime, Keygen, Status};
use crate::protocol::gg20::vss;
use curv::{
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::{DLogProof, ProveDLog},
    },
    elliptic::curves::traits::ECPoint,
    FE, GE,
};
use serde::{Deserialize, Serialize};
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

pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { criminals: Vec<Vec<Crime>> },
}

impl Keygen {
    pub(super) fn r3(&self) -> Output {
        assert!(matches!(self.status, Status::R2));
        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();

        let mut criminals = vec![Vec::new(); self.share_count];

        // check commitments
        // compute my_ecdsa_secret_key_share, ecdsa_public_key, all_ecdsa_public_key_shares
        let mut ecdsa_public_key = r1state.my_y_i;
        let mut my_ecdsa_secret_key_share = r2state.my_share_of_my_u_i;
        let mut all_ecdsa_public_key_shares: Vec<GE> = (0..self.share_count)
            // start each summation with my contribution
            .map(|i| vss::get_point_commitment(&r2state.my_u_i_share_commitments, i))
            .collect();
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
                criminals[i].push(Crime::R3BadReveal);
            }
            assert!(vss::validate_share(
                &r2bcast.u_i_share_commitments,
                &my_r2p2p.u_i_share,
                self.my_index
            )
            .is_ok());

            ecdsa_public_key = ecdsa_public_key + y_i;
            my_ecdsa_secret_key_share = my_ecdsa_secret_key_share + my_r2p2p.u_i_share;

            for (j, ecdsa_public_key_share) in all_ecdsa_public_key_shares.iter_mut().enumerate() {
                *ecdsa_public_key_share = *ecdsa_public_key_share
                    + vss::get_point_commitment(&r2bcast.u_i_share_commitments, j);
            }
        }

        if !criminals.iter().all(|c| c.is_empty()) {
            return Output::Fail { criminals };
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
