use super::{R1Bcast, R1P2p, R1State};
use crate::protocol::gg20::{keygen::SecretKeyShare, sign, vss};
use curv::{
    arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

pub fn start(
    key: &SecretKeyShare,
    participant_indices: &[usize],
) -> (R1State, R1Bcast, Vec<Option<R1P2p>>) {
    // TODO check participant_indices for length and duplicates
    let lagrangian_coefficient =
        vss::lagrangian_coefficient(key.share_count, key.my_index, participant_indices); // li
    let my_secret_key_summand = lagrangian_coefficient * key.my_ecdsa_secret_key_share; // w_i
    let my_secret_blind_summand = FE::new_random(); // gamma_i
    let my_public_blind_summand = GE::generator() * my_secret_blind_summand; // g_gamma_i
    let my_ecdsa_nonce_summand = FE::new_random(); // k_i
    let (my_commit, my_reveal) =
        HashCommitment::create_commitment(&my_public_blind_summand.bytes_compressed_to_big_int());

    // MtA protocol for my_ecdsa_nonce_summand * my_secret_blind_summand
    // TODO refactor?
    let mut out_p2p = Vec::with_capacity(participant_indices.len());
    let mut my_encrypted_ecdsa_nonce_summand_randomnesses =
        Vec::with_capacity(participant_indices.len()); // TODO do we need to store encryption randomness?
    for participant_index in participant_indices {
        if *participant_index == key.my_index {
            my_encrypted_ecdsa_nonce_summand_randomnesses.push(None);
            out_p2p.push(None);
            continue;
        }
        my_encrypted_ecdsa_nonce_summand_randomnesses
            .push(Some(Randomness::from(BigInt::sample_below(&key.my_ek.n))));
        let my_encrypted_ecdsa_nonce_summand = Paillier::encrypt_with_chosen_randomness(
            &key.my_ek,
            RawPlaintext::from(my_ecdsa_nonce_summand.to_big_int()),
            my_encrypted_ecdsa_nonce_summand_randomnesses
                .last()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        out_p2p.push(Some(R1P2p {
            my_encrypted_ecdsa_nonce_summand: my_encrypted_ecdsa_nonce_summand.into(),
        })); // use into() to avoid lifetime ugliness with RawCiphertext
    }

    (
        R1State {
            my_secret_key_summand,
            my_ecdsa_nonce_summand,
            my_reveal,
            my_encrypted_ecdsa_nonce_summand_randomnesses,
        },
        R1Bcast {
            my_commit,
            // TODO broadcast GE::generator() * key.my_ecdsa_secret_key_share ? https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_sign_client.rs#L138
        },
        out_p2p,
    )
}
