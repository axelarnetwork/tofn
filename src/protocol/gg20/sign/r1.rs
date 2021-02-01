use serde::{Deserialize, Serialize};

use crate::protocol::gg20::vss;
use curv::{
    arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use multi_party_ecdsa::utilities::mta;
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

use super::{Sign, Status};

// round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    my_commit: BigInt,
}
pub struct P2p {
    my_encrypted_ecdsa_nonce_summand: mta::MessageA,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    // key: SecretKeyShare,
    my_secret_key_summand: FE,
    my_ecdsa_nonce_summand: FE,
    // my_commit: BigInt, // for convenience: a copy of R1Bcast.commit
    my_reveal: BigInt, // decommit---to be released later
    my_encrypted_ecdsa_nonce_summand_randomnesses: Vec<Option<BigInt>>, // TODO do we need to store this?
}

impl Sign {
    // immutable &self: do not modify existing self state, only add more
    // TODO should we just mutate self directly instead?
    pub(super) fn r1(&self) -> (State, Bcast, Vec<Option<P2p>>) {
        assert!(matches!(self.status, Status::New));
        let lagrangian_coefficient = vss::lagrangian_coefficient(
            self.my_secret_key_share.share_count,
            self.my_secret_key_share.my_index,
            &self.participant_indices,
        ); // li
        let my_secret_key_summand =
            lagrangian_coefficient * self.my_secret_key_share.my_ecdsa_secret_key_share; // w_i
        let my_secret_blind_summand = FE::new_random(); // gamma_i
        let my_public_blind_summand = GE::generator() * my_secret_blind_summand; // g_gamma_i
        let my_ecdsa_nonce_summand = FE::new_random(); // k_i
        let (my_commit, my_reveal) = HashCommitment::create_commitment(
            &my_public_blind_summand.bytes_compressed_to_big_int(),
        );

        // initiate MtA protocols for
        // 1. my_ecdsa_nonce_summand (me) * my_secret_blind_summand (other)
        // 2. my_ecdsa_nonce_summand (me) * my_secret_key_summand (other)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both
        // we must encrypt my_ecdsa_nonce_summand separately for each other party using fresh randomness
        let mut out_p2p = Vec::with_capacity(self.participant_indices.len());
        let mut my_encrypted_ecdsa_nonce_summand_randomnesses =
            Vec::with_capacity(self.participant_indices.len()); // TODO do we need to store encryption randomness?
        for participant_index in self.participant_indices.iter() {
            if *participant_index == self.my_secret_key_share.my_index {
                my_encrypted_ecdsa_nonce_summand_randomnesses.push(None);
                out_p2p.push(None);
                continue;
            }

            let (my_encrypted_ecdsa_nonce_summand, my_encrypted_ecdsa_nonce_summand_randomness) =
                mta::MessageA::a(&my_ecdsa_nonce_summand, &self.my_secret_key_share.my_ek);

            my_encrypted_ecdsa_nonce_summand_randomnesses
                .push(Some(my_encrypted_ecdsa_nonce_summand_randomness));
            out_p2p.push(Some(P2p {
                my_encrypted_ecdsa_nonce_summand,
            }));
        }

        (
            State {
                my_secret_key_summand,
                my_ecdsa_nonce_summand,
                my_reveal,
                my_encrypted_ecdsa_nonce_summand_randomnesses,
            },
            Bcast {
                my_commit,
                // TODO broadcast GE::generator() * self.my_secret_key_share.my_ecdsa_secret_key_share ? https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_sign_client.rs#L138
            },
            out_p2p,
        )
    }
}
