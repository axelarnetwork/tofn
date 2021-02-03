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

    // TEST: indices are correct
    for p in participants.iter() {
        assert_eq!(
            participant_indices[p.my_participant_index],
            p.my_secret_key_share.my_index
        );
    }

    let one: FE = ECScalar::from(&BigInt::from(1));

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

    // TEST: secret key shares yield the pubkey
    let ecdsa_secret_key = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().my_secret_key_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    let test_pubkey = GE::generator() * ecdsa_secret_key;
    assert_eq!(test_pubkey.get_element(), key_shares[0].ecdsa_public_key);

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

    // execute round 3 all participants and store their outputs
    let mut all_r3_bcasts = FillVec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r3();
        participant.r3state = Some(state);
        participant.status = Status::R3;
        all_r3_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 3 msgs
    for participant in participants.iter_mut() {
        participant.in_r3bcasts = all_r3_bcasts.clone();
    }

    // TEST: MtA for nonce_x_blind (delta_i), nonce_x_keyshare (sigma_i)
    let nonce = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().my_ecdsa_nonce_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    let blind = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().my_secret_blind_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    let nonce_x_blind = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().my_nonce_x_blind_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    assert_eq!(nonce_x_blind, nonce * blind);
    let nonce_x_keyshare = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().my_nonce_x_keyshare_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    assert_eq!(nonce_x_keyshare, nonce * ecdsa_secret_key);

    // execute round 4 all participants and store their outputs
    let mut all_r4_bcasts = FillVec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r4();
        participant.r4state = Some(state);
        participant.status = Status::R4;
        all_r4_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 4 msgs
    for participant in participants.iter_mut() {
        participant.in_r4bcasts = all_r4_bcasts.clone();
    }

    // TEST: everyone correctly computed nonce_x_blind (delta = k*gamma)
    for nonce_x_blind_inv in participants
        .iter()
        .map(|p| p.r4state.as_ref().unwrap().nonce_x_blind_inv)
    {
        assert_eq!(nonce_x_blind_inv * nonce_x_blind, one);
    }

    // execute round 5 all participants and store their outputs
    let mut all_r5_bcasts = FillVec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r5();
        participant.r5state = Some(state);
        participant.status = Status::R5;
        all_r5_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 5 msgs
    for participant in participants.iter_mut() {
        participant.in_r5bcasts = all_r5_bcasts.clone();
    }

    // execute round 6 all participants and store their outputs
    let mut all_r6_bcasts = FillVec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r6();
        participant.r6state = Some(state);
        participant.status = Status::R6;
        all_r6_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 6 msgs
    for participant in participants.iter_mut() {
        participant.in_r6bcasts = all_r6_bcasts.clone();
    }

    // execute round 7 all participants and store their outputs
    let mut all_r7_bcasts = FillVec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r7();
        participant.r7state = Some(state);
        participant.status = Status::R7;
        all_r7_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 6 msgs
    for participant in participants.iter_mut() {
        participant.in_r7bcasts = all_r7_bcasts.clone();
    }
}
