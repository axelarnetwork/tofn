use super::{Keygen, Status};
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
    pub(super) ecdsa_public_key: GE,          // the final pub key
    pub(super) my_ecdsa_secret_key_share: FE, // my final secret key share
}

impl Keygen {
    pub(super) fn r3(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R2));
        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();

        let mut ecdsa_public_key = r1state.my_ecdsa_public_summand;
        let mut my_secret_key_share = r2state.my_share_of_my_ecdsa_secret_summand;

        for i in 0..self.share_count {
            if i == self.my_index {
                continue;
            }
            let bcast = self.in_r2bcasts.vec_ref()[i].clone().unwrap_or_else(|| {
                panic!(
                    "party {} says: missing bcast input for party {}",
                    self.my_index, i
                )
            });
            let p2p = self.in_r2p2ps.vec_ref()[i].clone().unwrap_or_else(|| {
                panic!(
                    "party {} says: missing p2p input for party {}",
                    self.my_index, i
                )
            });
            let ecdsa_public_summand = &bcast.secret_share_commitments[0];
            let com = HashCommitment::create_commitment_with_user_defined_randomness(
                &ecdsa_public_summand.bytes_compressed_to_big_int(),
                &bcast.reveal,
            );
            assert!(r2state.all_commits[i] == com);
            assert!(vss::validate_share(
                &bcast.secret_share_commitments,
                &p2p.ecdsa_secret_summand_share,
                self.my_index
            )
            .is_ok());

            ecdsa_public_key = ecdsa_public_key + ecdsa_public_summand;
            my_secret_key_share = my_secret_key_share + p2p.ecdsa_secret_summand_share;
        }

        let my_bcast = Bcast {
            dlog_proof: DLogProof::prove(&my_secret_key_share),
        };
        (
            State {
                ecdsa_public_key,
                my_ecdsa_secret_key_share: my_secret_key_share,
            },
            my_bcast,
        )
    }
}
