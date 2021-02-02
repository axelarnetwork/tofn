use super::*;
use crate::protocol::{
    gg20::keygen::{self, SecretKeyShare},
    tests,
};
use curv::{
    // FE, // rustc does not warn of unused imports for FE
    arithmetic::traits::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    elliptic::curves::traits::{ECPoint, ECScalar},
};
use keygen::stateless::tests::execute_keygen;

#[test]
fn sign() {
    let key_shares = execute_keygen(5, 2);
    let participant_indices = vec![1, 2, 4];
    execute_sign(&key_shares, &participant_indices);
}

fn execute_sign(key_shares: &[SecretKeyShare], participant_indices: &[usize]) {
    let mut participants: Vec<Sign> = participant_indices
        .iter()
        .map(|i| Sign::new(&key_shares[*i], participant_indices))
        .collect();

    // execute round 1 all participants and store their outputs
    let mut all_r1_bcasts = FillVec::with_capacity(participants.len());
    let mut all_r1_p2ps = vec![FillVec::with_capacity(participants.len()); participants.len()];
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast, p2ps) = participant.r1();
        participant.r1state = Some(state);
        participant.status = Status::R1;
        all_r1_bcasts.insert(i, bcast).unwrap();

        // route p2p msgs
        for (j, p2p) in p2ps.into_iter().enumerate() {
            if let Some(p2p) = p2p {
                all_r1_p2ps[j].insert(i, p2p).unwrap();
            }
        }
    }

    // deliver round 1 msgs
    for (participant, r1_p2ps) in participants.iter_mut().zip(all_r1_p2ps.into_iter()) {
        participant.in_r1p2ps = r1_p2ps;
        participant.in_r1bcasts = all_r1_bcasts.clone();
    }

    // execute round 2 all participants and store their outputs
    let mut all_r2_p2ps = vec![FillVec::with_capacity(participants.len()); participants.len()];
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, p2ps) = participant.r2();
        participant.r2state = Some(state);
        participant.status = Status::R2;

        // route p2p msgs
        for (j, p2p) in p2ps.into_iter().enumerate() {
            if let Some(p2p) = p2p {
                all_r2_p2ps[j].insert(i, p2p).unwrap();
            }
        }
    }

    // deliver round 2 msgs
    for (participant, r2_p2ps) in participants.iter_mut().zip(all_r2_p2ps.into_iter()) {
        participant.in_r2p2ps = r2_p2ps;
    }

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
