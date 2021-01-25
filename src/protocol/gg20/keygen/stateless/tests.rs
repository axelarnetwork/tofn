use super::*;
use crate::protocol::tests::TEST_CASES;
use curv::{
    // FE, // rustc does not warn of unused imports for FE
    cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    elliptic::curves::traits::{ECPoint, ECScalar},
};

#[test]
fn keygen() {
    for test_case in &TEST_CASES {
        execute_keygen(test_case.0, test_case.1);
    }
}

fn execute_keygen(share_count: usize, threshold: usize) {
    assert!(threshold < share_count);

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
        all_vss_indices.push(state.my_share_index - 1); // careful! curv library adds 1 to indices
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
    for state in all_r4_states {
        let test_pubkey = GE::generator() * secret_key_reconstructed;
        assert_eq!(test_pubkey.get_element(), state.ecdsa_public_key);
    }
}
