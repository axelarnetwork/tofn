use crate::protocol::gg20::keygen::tests::{TEST_CASES, TEST_CASES_INVALID};

use super::*;
use curv::{
    // FE, // rustc does not warn of unused imports for FE
    cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    elliptic::curves::traits::{ECPoint, ECScalar},
};

#[test]
fn keygen() {
    for &(share_count, threshold) in TEST_CASES.iter() {
        execute_keygen(share_count, threshold);
    }

    // TODO refactor so there's no need to catch panics
    // silence terminal output from catch_unwind https://stackoverflow.com/questions/35559267/suppress-panic-output-in-rust-when-using-paniccatch-unwind/35559417#35559417
    std::panic::set_hook(Box::new(|_| {}));
    for &(share_count, threshold) in TEST_CASES_INVALID.iter() {
        assert!(std::panic::catch_unwind(|| execute_keygen(share_count, threshold)).is_err());
    }
}

pub fn execute_keygen(share_count: usize, threshold: usize) -> Vec<super::super::SecretKeyShare> {
    // execute round 1 all parties and store their outputs
    let mut all_r1_bcasts = Vec::with_capacity(share_count);
    let mut all_r1_states = Vec::with_capacity(share_count);
    for i in 0..share_count {
        let (state, bcast) = r1::start(share_count, threshold, i);
        all_r1_states.push(state);
        all_r1_bcasts.push(Some(bcast));
    }
    let all_r1_bcasts = all_r1_bcasts; // make read-only

    // save each u for later tests
    let all_u_secrets: Vec<FE> = all_r1_states
        .iter()
        .map(|v| v.my_ecdsa_secret_summand)
        .collect();

    // execute round 2 all parties and store their outputs
    let mut all_r2_states = Vec::with_capacity(share_count);
    let mut all_r2_bcasts = Vec::with_capacity(share_count);
    let mut all_r2_p2ps = Vec::with_capacity(share_count);
    for r1_state in all_r1_states {
        let (state, bcast, p2ps) = r2::execute(&r1_state, &all_r1_bcasts);
        all_r2_states.push(state);
        all_r2_bcasts.push(Some(bcast));
        all_r2_p2ps.push(p2ps);
    }
    let all_r2_bcasts = all_r2_bcasts; // make read-only
    let all_r2_p2ps = all_r2_p2ps; // make read-only

    // route p2p msgs for round 3
    let mut all_r2_p2ps_delivered = vec![Vec::with_capacity(share_count); share_count];
    for r2_p2ps in all_r2_p2ps {
        for (j, r2_p2p) in r2_p2ps.into_iter().enumerate() {
            all_r2_p2ps_delivered[j].push(r2_p2p);
        }
    }

    // execute round 3 all parties and store their outputs
    let mut all_r3_states = Vec::with_capacity(share_count);
    let mut all_r3_bcasts = Vec::with_capacity(share_count);
    for (i, r2_state) in all_r2_states.into_iter().enumerate() {
        let (state, bcast) = r3::execute(&r2_state, &all_r2_bcasts, &all_r2_p2ps_delivered[i]);
        all_r3_states.push(state);
        all_r3_bcasts.push(Some(bcast));
    }
    let all_r3_bcasts = all_r3_bcasts; // make read-only

    // execute round 4 all parties and store their outputs
    let mut all_r4_states = Vec::with_capacity(share_count);
    for r3_state in all_r3_states {
        let result = r4::execute(&r3_state, &all_r3_bcasts);

        // TODO transitory
        let result = super::super::SecretKeyShare {
            share_count: result.share_count,
            threshold: result.threshold,
            my_index: result.my_index,
            my_dk: result.my_dk,
            my_ek: result.my_ek,
            my_ecdsa_secret_key_share: result.my_ecdsa_secret_key_share,
            ecdsa_public_key: result.ecdsa_public_key,
            all_eks: result.all_eks,
        };

        all_r4_states.push(result);
    }
    let all_r4_states = all_r4_states; // make read-only

    // test: reconstruct the secret key in two ways:
    // 1. from all the u secrets of round 1
    // 2. from the first t+1 shares
    let secret_key_sum_u = all_u_secrets.iter().fold(FE::zero(), |acc, x| acc + x);

    let mut all_vss_indices = Vec::<usize>::with_capacity(share_count);
    let mut all_secret_shares = Vec::<FE>::with_capacity(share_count);
    for state in &all_r4_states {
        all_vss_indices.push(state.my_index);
        all_secret_shares.push(state.my_ecdsa_secret_key_share);
    }
    let test_vss_scheme = VerifiableSS {
        // cruft: needed for curv library
        parameters: ShamirSecretSharing {
            share_count,
            threshold,
        },
        commitments: Vec::new(),
    };
    let secret_key_reconstructed = test_vss_scheme.reconstruct(
        &all_vss_indices[0..=threshold],
        &all_secret_shares[0..=threshold],
    );

    assert_eq!(secret_key_reconstructed, secret_key_sum_u);

    // test: verify that the reconstructed secret key yields the public key everyone deduced
    for state in all_r4_states.iter() {
        let test_pubkey = GE::generator() * secret_key_reconstructed;
        assert_eq!(test_pubkey, state.ecdsa_public_key);
    }

    // print each key share
    // output may be copied into src/gg20/sign/stateless/tests.rs
    // println!(
    //     "share_count: {}, threshold: {}",
    //     all_r4_states[0].share_count, all_r4_states[0].threshold
    // );
    // println!(
    //     "ecdsa_public_key: {:?}",
    //     all_r4_states[0].ecdsa_public_key.serialize()
    // );
    // for key_share in all_r4_states.iter() {
    //     println!(
    //         "my_index: {}, my_ecdsa_secret_key_share: {:?}",
    //         key_share.my_index, key_share.my_ecdsa_secret_key_share
    //     );
    // }

    all_r4_states
}
