use super::*;
use crate::protocol::{tests::execute_protocol_vec, Protocol};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};

lazy_static::lazy_static! {
    pub static ref TEST_CASES: Vec<(usize,usize)> // (share_count, threshold)
    // = vec![(5,3)];
    = vec![(5, 0), (5, 1), (5, 3), (5, 4)];
    pub static ref TEST_CASES_INVALID: Vec<(usize,usize)> = vec![(5, 5), (5, 6), (2, 4)];
}

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

// pub(in super::super) so that sign module can see execute_keygen
pub(in super::super) fn execute_keygen(
    share_count: usize,
    threshold: usize,
) -> Vec<SecretKeyShare> {
    let mut parties: Vec<Keygen> = (0..share_count)
        .map(|i| Keygen::new(share_count, threshold, i).unwrap())
        .collect();

    // execute round 1 all parties and store their outputs
    let mut all_r1_bcasts = FillVec::with_len(share_count);
    for (i, party) in parties.iter_mut().enumerate() {
        let (state, bcast) = party.r1();
        party.r1state = Some(state);
        party.status = Status::R1;
        all_r1_bcasts.insert(i, bcast).unwrap();
    }
    let all_r1_bcasts = all_r1_bcasts; // make read-only

    // deliver round 3 msgs
    for party in parties.iter_mut() {
        party.in_r1bcasts = all_r1_bcasts.clone();
    }

    // save each u for later tests
    let all_u_secrets: Vec<FE> = parties
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().my_ecdsa_secret_summand)
        .collect();

    // execute round 2 all parties and store their outputs
    let mut all_r2_bcasts = FillVec::with_len(share_count);
    let mut all_r2_p2ps = vec![FillVec::with_len(share_count); share_count];
    for (i, party) in parties.iter_mut().enumerate() {
        let (state, bcast, p2ps) = party.r2();
        party.r2state = Some(state);
        party.status = Status::R2;
        all_r2_bcasts.insert(i, bcast).unwrap();

        // route p2p msgs
        for (j, p2p) in p2ps.into_iter().enumerate() {
            if let Some(p2p) = p2p {
                all_r2_p2ps[j].insert(i, p2p).unwrap();
            }
        }
    }
    let all_r2_bcasts = all_r2_bcasts; // make read-only
    let all_r2_p2ps = all_r2_p2ps; // make read-only

    // deliver round 2 msgs
    for (party, r2_p2ps) in parties.iter_mut().zip(all_r2_p2ps.into_iter()) {
        party.in_r2p2ps = r2_p2ps;
        party.in_r2bcasts = all_r2_bcasts.clone();
    }

    // execute round 3 all parties and store their outputs
    let mut all_r3_bcasts = FillVec::with_len(share_count);
    for (i, party) in parties.iter_mut().enumerate() {
        let (state, bcast) = party.r3();
        party.r3state = Some(state);
        party.status = Status::R3;
        all_r3_bcasts.insert(i, bcast).unwrap();
    }
    let all_r3_bcasts = all_r3_bcasts; // make read-only

    // deliver round 3 msgs
    for party in parties.iter_mut() {
        party.in_r3bcasts = all_r3_bcasts.clone();
    }

    // execute round 4 all parties and store their outputs
    let mut all_secret_key_shares = Vec::with_capacity(share_count);
    for party in parties.iter_mut() {
        let secret_key_share = party.r4();
        party.status = Status::Done;
        all_secret_key_shares.push(secret_key_share);
    }
    let all_secret_key_shares = all_secret_key_shares; // make read-only

    // test: reconstruct the secret key in two ways:
    // 1. from all the u secrets of round 1
    // 2. from the first t+1 shares
    let secret_key_sum_u = all_u_secrets.iter().fold(FE::zero(), |acc, x| acc + x);

    let mut all_vss_indices = Vec::<usize>::with_capacity(share_count);
    let mut all_secret_shares = Vec::<FE>::with_capacity(share_count);
    for secret_key_share in all_secret_key_shares.iter() {
        all_vss_indices.push(secret_key_share.my_index);
        all_secret_shares.push(secret_key_share.my_ecdsa_secret_key_share);
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
    for state in all_secret_key_shares.iter() {
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

    all_secret_key_shares
}

#[test]
fn keygen_protocol() {
    for &(share_count, threshold) in TEST_CASES.iter() {
        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut keygen_protocols: Vec<Keygen> = (0..share_count)
            .map(|i| Keygen::new(share_count, threshold, i).unwrap())
            .collect();
        let mut protocols: Vec<&mut dyn Protocol> = keygen_protocols
            .iter_mut()
            .map(|p| p as &mut dyn Protocol)
            .collect();
        execute_protocol_vec(&mut protocols);
    }

    for (i, &(share_count, threshold)) in TEST_CASES_INVALID.iter().enumerate() {
        assert!(Keygen::new(share_count, threshold, i).is_err());
    }
}
