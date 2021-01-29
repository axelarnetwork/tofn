use super::*;
use crate::protocol::gg20::keygen::{self, SecretKeyShare};
use curv::{
    // FE, // rustc does not warn of unused imports for FE
    arithmetic::traits::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    elliptic::curves::traits::{ECPoint, ECScalar},
};

#[test]
fn sign() {
    // the following test data was produced by src/protocol/gg20/keygen/stateles/tests.rs:
    // ```
    // share_count: 5, threshold: 2
    // ecdsa_public_key: [2, 69, 215, 78, 124, 124, 215, 81, 82, 117, 116, 164, 251, 27, 52, 58, 33, 252, 210, 150, 20, 113, 38, 151, 220, 56, 94, 204, 156, 112, 71, 68, 192]
    // my_index: 0, my_ecdsa_secret_key_share: Secp256k1Scalar { purpose: "add", fe: SecretKey(2a2f9322f44c274c8f6f147f765556813177da42304601aca50513758358aed5) }
    // my_index: 1, my_ecdsa_secret_key_share: Secp256k1Scalar { purpose: "add", fe: SecretKey(fdeef8474731d8cb150761977dc01fef622b88eb6bc218c80904c93b98547e5f) }
    // my_index: 2, my_ecdsa_secret_key_share: Secp256k1Scalar { purpose: "add", fe: SecretKey(e3422f5aa45b0fb7975ae4455f122a299404208e0c08fd7ec7084f13e1e61c2f) }
    // my_index: 3, my_ecdsa_secret_key_share: Secp256k1Scalar { purpose: "add", fe: SecretKey(da29385d0bc7cc1216699c891a4b752e81b07e10c063500c9ee2038b3043c986) }
    // my_index: 4, my_ecdsa_secret_key_share: Secp256k1Scalar { purpose: "add", fe: SecretKey(e2a4134e7d780dda92338a62af6c00fe2b30a17388d110719091e6a1836d8664) }
    // ```
    let (share_count, threshold) = (5, 2);
    let ecdsa_public_key = PK::from_slice(&[
        2, 69, 215, 78, 124, 124, 215, 81, 82, 117, 116, 164, 251, 27, 52, 58, 33, 252, 210, 150,
        20, 113, 38, 151, 220, 56, 94, 204, 156, 112, 71, 68, 192,
    ])
    .unwrap();
    let key_shares = vec![
        SecretKeyShare {
            share_count,
            threshold,
            my_index: 0,
            my_ecdsa_secret_key_share: ECScalar::from(&BigInt::from_hex(
                "2a2f9322f44c274c8f6f147f765556813177da42304601aca50513758358aed5",
            )),
            ecdsa_public_key,
        },
        SecretKeyShare {
            share_count,
            threshold,
            my_index: 1,
            my_ecdsa_secret_key_share: ECScalar::from(&BigInt::from_hex(
                "fdeef8474731d8cb150761977dc01fef622b88eb6bc218c80904c93b98547e5f",
            )),
            ecdsa_public_key,
        },
        SecretKeyShare {
            share_count,
            threshold,
            my_index: 2,
            my_ecdsa_secret_key_share: ECScalar::from(&BigInt::from_hex(
                "e3422f5aa45b0fb7975ae4455f122a299404208e0c08fd7ec7084f13e1e61c2f",
            )),
            ecdsa_public_key,
        },
        SecretKeyShare {
            share_count,
            threshold,
            my_index: 3,
            my_ecdsa_secret_key_share: ECScalar::from(&BigInt::from_hex(
                "da29385d0bc7cc1216699c891a4b752e81b07e10c063500c9ee2038b3043c986",
            )),
            ecdsa_public_key,
        },
        SecretKeyShare {
            share_count,
            threshold,
            my_index: 4,
            my_ecdsa_secret_key_share: ECScalar::from(&BigInt::from_hex(
                "e2a4134e7d780dda92338a62af6c00fe2b30a17388d110719091e6a1836d8664",
            )),
            ecdsa_public_key,
        },
    ];
    let participant_indices = vec![1, 2, 4];
    execute_sign(&key_shares, &participant_indices);
}

fn execute_sign(key_shares: &[SecretKeyShare], participant_indices: &[usize]) {
    let share_count = key_shares[0].share_count;

    // execute round 1 all parties and store their outputs
    let mut all_r1_bcasts = Vec::with_capacity(share_count);
    let mut all_r1_states = Vec::with_capacity(share_count);
    for key_share in key_shares {
        let (state, bcast) = r1::start(key_share, participant_indices);
        all_r1_states.push(state);
        all_r1_bcasts.push(Some(bcast));
    }
    let all_r1_bcasts = all_r1_bcasts; // make read-only

    // // save each u for later tests
    // let all_u_secrets: Vec<FE> = all_r1_states
    //     .iter()
    //     .map(|v| v.my_ecdsa_secret_summand)
    //     .collect();

    // // execute round 2 all parties and store their outputs
    // let mut all_r2_states = Vec::with_capacity(share_count);
    // let mut all_r2_bcasts = Vec::with_capacity(share_count);
    // let mut all_r2_p2ps = Vec::with_capacity(share_count);
    // for r1_state in all_r1_states {
    //     let (state, bcast, p2ps) = r2::execute(&r1_state, &all_r1_bcasts);
    //     all_r2_states.push(state);
    //     all_r2_bcasts.push(Some(bcast));
    //     all_r2_p2ps.push(p2ps);
    // }
    // let all_r2_bcasts = all_r2_bcasts; // make read-only
    // let all_r2_p2ps = all_r2_p2ps; // make read-only

    // // route p2p msgs for round 3
    // let mut all_r2_p2ps_delivered = vec![Vec::with_capacity(share_count); share_count];
    // for r2_p2ps in all_r2_p2ps {
    //     for (j, r2_p2p) in r2_p2ps.into_iter().enumerate() {
    //         all_r2_p2ps_delivered[j].push(r2_p2p);
    //     }
    // }

    // // execute round 3 all parties and store their outputs
    // let mut all_r3_states = Vec::with_capacity(share_count);
    // let mut all_r3_bcasts = Vec::with_capacity(share_count);
    // for (i, r2_state) in all_r2_states.into_iter().enumerate() {
    //     let (state, bcast) = r3::execute(&r2_state, &all_r2_bcasts, &all_r2_p2ps_delivered[i]);
    //     all_r3_states.push(state);
    //     all_r3_bcasts.push(Some(bcast));
    // }
    // let all_r3_bcasts = all_r3_bcasts; // make read-only

    // // execute round 4 all parties and store their outputs
    // let mut all_r4_states = Vec::with_capacity(share_count);
    // for r3_state in all_r3_states {
    //     let result = r4::execute(&r3_state, &all_r3_bcasts);
    //     all_r4_states.push(result);
    // }
    // let all_r4_states = all_r4_states; // make read-only

    // // test: reconstruct the secret key in two ways:
    // // 1. from all the u secrets of round 1
    // // 2. from the first t+1 shares
    // let secret_key_sum_u = all_u_secrets.iter().fold(FE::zero(), |acc, x| acc + x);

    // let mut all_vss_indices = Vec::<usize>::with_capacity(share_count);
    // let mut all_secret_shares = Vec::<FE>::with_capacity(share_count);
    // for state in &all_r4_states {
    //     all_vss_indices.push(state.my_share_index - 1); // careful! curv library adds 1 to indices
    //     all_secret_shares.push(state.my_ecdsa_secret_key_share);
    // }
    // let test_vss_scheme = VerifiableSS {
    //     // cruft: needed for curv library
    //     parameters: ShamirSecretSharing {
    //         share_count,
    //         threshold,
    //     },
    //     commitments: Vec::new(),
    // };
    // let secret_key_reconstructed = test_vss_scheme.reconstruct(
    //     &all_vss_indices[0..=threshold],
    //     &all_secret_shares[0..=threshold],
    // );

    // assert_eq!(secret_key_reconstructed, secret_key_sum_u);

    // // test: verify that the reconstructed secret key yields the public key everyone deduced
    // for state in all_r4_states {
    //     let test_pubkey = GE::generator() * secret_key_reconstructed;
    //     assert_eq!(test_pubkey.get_element(), state.ecdsa_public_key);
    // }
}
