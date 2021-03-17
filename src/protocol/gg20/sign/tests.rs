use super::*;
use crate::protocol::{
    gg20::keygen::{self, SecretKeyShare},
    tests::execute_protocol_vec,
    Protocol,
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use k256::{ecdsa::Signature, FieldBytes};
use keygen::tests::execute_keygen;

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    static ref TEST_CASES: Vec<(usize, usize, Vec<usize>)> = vec![ // (share_count, threshold, participant_indices)
        // (5, 2, vec![1,2,4]),
        (5, 2, vec![4,1,2]),
        // (5, 2, vec![0,1,2,3]),
        // (5, 2, vec![4,2,3,1,0]),
        (1,0,vec![0]),
    ];
    // TODO add TEST_CASES_INVALID
}

#[test]
fn sign() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        let key_shares = execute_keygen(*share_count, *threshold);
        execute_sign(&key_shares, participant_indices, &MSG_TO_SIGN);
    }
}

fn execute_sign(key_shares: &[SecretKeyShare], participant_indices: &[usize], msg_to_sign: &[u8]) {
    let mut participants: Vec<Sign> = participant_indices
        .iter()
        .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
        .collect();

    // TEST: indices are correct
    for p in participants.iter() {
        assert_eq!(
            p.participant_indices[p.my_participant_index],
            p.my_secret_key_share.my_index
        );
    }

    let one: FE = ECScalar::from(&BigInt::from(1));

    // execute round 1 all participants and store their outputs
    let mut all_r1_bcasts = FillVec::with_len(participants.len());
    let mut all_r1_p2ps = Vec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast, p2ps) = participant.r1();
        participant.r1state = Some(state);
        participant.status = Status::R1;
        all_r1_bcasts.insert(i, bcast).unwrap();
        all_r1_p2ps.push(p2ps);
    }

    // deliver round 1 msgs
    for participant in participants.iter_mut() {
        participant.in_r1p2ps = all_r1_p2ps.clone();
        participant.in_r1bcasts = all_r1_bcasts.clone();
    }

    // TEST: secret key shares yield the pubkey
    let ecdsa_secret_key = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().my_secret_key_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    let ecdsa_public_key = GE::generator() * ecdsa_secret_key;
    for key_share in key_shares.iter() {
        assert_eq!(ecdsa_public_key, key_share.ecdsa_public_key);
    }

    // execute round 2 all participants and store their outputs
    let mut all_r2_p2ps = vec![FillVec::with_len(participants.len()); participants.len()];
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
    let mut all_r3_bcasts = FillVec::with_len(participants.len());
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

    // TEST: MtA for nonce_x_blind (delta_i), nonce_x_secret_key (sigma_i)
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
    let nonce_x_secret_key = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().my_nonce_x_keyshare_summand)
        .fold(FE::zero(), |acc, x| acc + x);
    assert_eq!(nonce_x_secret_key, nonce * ecdsa_secret_key);

    // execute round 4 all participants and store their outputs
    let mut all_r4_bcasts = FillVec::with_len(participants.len());
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
    let mut all_r5_bcasts = FillVec::with_len(participants.len());
    let mut all_r5_p2ps = vec![FillVec::with_len(participants.len()); participants.len()];
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast, p2ps) = participant.r5();
        participant.r5state = Some(state);
        participant.status = Status::R5;
        all_r5_bcasts.insert(i, bcast).unwrap();

        // route p2p msgs
        for (j, p2p) in p2ps.into_iter().enumerate() {
            if let Some(p2p) = p2p {
                all_r5_p2ps[j].insert(i, p2p).unwrap();
            }
        }
    }

    // deliver round 5 msgs
    for (participant, r5_p2ps) in participants.iter_mut().zip(all_r5_p2ps.into_iter()) {
        participant.in_r5p2ps = r5_p2ps;
        participant.in_r5bcasts = all_r5_bcasts.clone();
    }

    // TEST: everyone correctly computed ecdsa_randomizer (R)
    let randomizer = GE::generator() * nonce.invert();
    for ecdsa_randomizer in participants
        .iter()
        .map(|p| p.r5state.as_ref().unwrap().ecdsa_randomizer)
    {
        assert_eq!(ecdsa_randomizer, randomizer);
    }

    // execute round 6 all participants and store their outputs
    let mut all_r6_bcasts = FillVec::with_len(participants.len());
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
    let mut all_r7_bcasts = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast) = participant.r7();
        participant.r7state = Some(state);
        participant.status = Status::R7;
        all_r7_bcasts.insert(i, bcast).unwrap();
    }

    // deliver round 7 msgs
    for participant in participants.iter_mut() {
        participant.in_r7bcasts = all_r7_bcasts.clone();
    }

    // execute round 8 all participants and store their outputs
    let mut all_sigs = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let sig = participant.r8();
        participant.status = Status::Done;
        all_sigs.insert(i, sig).unwrap();
    }

    // TEST: everyone correctly computed the signature
    let msg_to_sign = ECScalar::from(&BigInt::from(msg_to_sign));
    let r: FE = ECScalar::from(&randomizer.x_coor().unwrap().mod_floor(&FE::q()));
    let s: FE = nonce * (msg_to_sign + ecdsa_secret_key * r);
    let s = {
        // normalize s
        let s_bigint = s.to_big_int();
        let s_neg = FE::q() - &s_bigint;
        if s_bigint > s_neg {
            ECScalar::from(&s_neg)
        } else {
            s
        }
    };
    for sig in all_sigs
        .vec_ref()
        .iter()
        .map(|opt| Signature::from_asn1(opt.as_ref().unwrap().as_bytes()).unwrap())
    {
        let (sig_r, sig_s) = (sig.r(), sig.s());
        let (sig_r, sig_s): (FieldBytes, FieldBytes) = (From::from(sig_r), From::from(sig_s));
        let (sig_r, sig_s) = (sig_r.as_slice(), sig_s.as_slice());
        let (sig_r, sig_s): (BigInt, BigInt) = (BigInt::from(sig_r), BigInt::from(sig_s));
        assert_eq!(sig_r, r.to_big_int());
        assert_eq!(sig_s, s.to_big_int());
    }

    let sig = EcdsaSig { r, s };
    assert!(sig.verify(&ecdsa_public_key, &msg_to_sign));
}

// #[test]
// fn sign_protocol() {
//     for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
//         let key_shares = execute_keygen(*share_count, *threshold);

//         // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
//         let mut participants: Vec<Sign> = participant_indices
//             .iter()
//             .map(|i| Sign::new(&key_shares[*i], &participant_indices, &MSG_TO_SIGN).unwrap())
//             .collect();
//         let mut protocols: Vec<&mut dyn Protocol> = participants
//             .iter_mut()
//             .map(|p| p as &mut dyn Protocol)
//             .collect();
//         execute_protocol_vec(&mut protocols);
//     }
// }
