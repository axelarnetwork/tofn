use serde::{Deserialize, Serialize};

use crate::protocol::gg20::vss;
use curv::{
    arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

use super::{Sign, Status};

// round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    my_commit: BigInt,
}
pub struct P2p {
    my_encrypted_ecdsa_nonce_summand: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    // key: SecretKeyShare,
    my_secret_key_summand: FE,
    my_ecdsa_nonce_summand: FE,
    // my_commit: BigInt, // for convenience: a copy of R1Bcast.commit
    my_reveal: BigInt, // decommit---to be released later
    my_encrypted_ecdsa_nonce_summand_randomnesses: Vec<Option<Randomness>>, // TODO do we need to store this?
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

        // MtA protocol for my_ecdsa_nonce_summand * my_secret_blind_summand
        // TODO refactor?
        let mut out_p2p = Vec::with_capacity(self.participant_indices.len());
        let mut my_encrypted_ecdsa_nonce_summand_randomnesses =
            Vec::with_capacity(self.participant_indices.len()); // TODO do we need to store encryption randomness?
        for participant_index in self.participant_indices.iter() {
            if *participant_index == self.my_secret_key_share.my_index {
                my_encrypted_ecdsa_nonce_summand_randomnesses.push(None);
                out_p2p.push(None);
                continue;
            }
            my_encrypted_ecdsa_nonce_summand_randomnesses.push(Some(Randomness::from(
                BigInt::sample_below(&self.my_secret_key_share.my_ek.n),
            )));
            let my_encrypted_ecdsa_nonce_summand = Paillier::encrypt_with_chosen_randomness(
                &self.my_secret_key_share.my_ek,
                RawPlaintext::from(my_ecdsa_nonce_summand.to_big_int()),
                my_encrypted_ecdsa_nonce_summand_randomnesses
                    .last()
                    .unwrap()
                    .as_ref()
                    .unwrap(),
            );
            out_p2p.push(Some(P2p {
                my_encrypted_ecdsa_nonce_summand: my_encrypted_ecdsa_nonce_summand.into(), // use into() to avoid lifetime ugliness with RawCiphertext
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
