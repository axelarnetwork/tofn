use super::*;
use crate::{
    protocol::{
        gg20::keygen::{self, SecretKeyShare},
        tests::{execute_protocol_vec, execute_protocol_vec_self_delivery},
        Protocol,
    },
    zkp::range::tests::corrupt_proof,
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
        participant.in_all_r1p2ps = all_r1_p2ps.clone();
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
    let mut all_r2_p2ps = Vec::with_capacity(participants.len());
    for participant in participants.iter_mut() {
        match participant.r2() {
            r2::Output::Success { state, out_p2ps } => {
                participant.r2state = Some(state);
                participant.status = Status::R2;
                all_r2_p2ps.push(out_p2ps);
            }
            r2::Output::Fail { out_bcast } => {
                panic!(
                    "r2 party {} expect success got failure with culprits: {:?}",
                    participant.my_secret_key_share.my_index, out_bcast
                );
            }
        }
    }

    // deliver round 2 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r2p2ps = all_r2_p2ps.clone();
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
    let mut all_r5_p2ps = Vec::with_capacity(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let (state, bcast, p2ps) = participant.r5();
        participant.r5state = Some(state);
        participant.status = Status::R5;
        all_r5_bcasts.insert(i, bcast).unwrap();
        all_r5_p2ps.push(p2ps);
    }

    // deliver round 5 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r5p2ps = all_r5_p2ps.clone();
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

#[test]
fn sign_protocol() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        let key_shares = execute_keygen(*share_count, *threshold);

        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut participants: Vec<Sign> = participant_indices
            .iter()
            .map(|i| Sign::new(&key_shares[*i], &participant_indices, &MSG_TO_SIGN).unwrap())
            .collect();
        let mut protocols: Vec<&mut dyn Protocol> = participants
            .iter_mut()
            .map(|p| p as &mut dyn Protocol)
            .collect();
        execute_protocol_vec(&mut protocols);
    }
}

#[test]
fn sign_protocol_with_self_delivery() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        let key_shares = execute_keygen(*share_count, *threshold);

        // TODO refactor copied code from sign_protocol
        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut participants: Vec<Sign> = participant_indices
            .iter()
            .map(|i| Sign::new(&key_shares[*i], &participant_indices, &MSG_TO_SIGN).unwrap())
            .collect();
        let mut protocols: Vec<&mut dyn Protocol> = participants
            .iter_mut()
            .map(|p| p as &mut dyn Protocol)
            .collect();
        execute_protocol_vec_self_delivery(&mut protocols, true);
    }
}

// TODO move these tests into r3fail module
#[test]
fn sign_fault_r2_bad_proof() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        if *share_count < 2 {
            continue; // need at least 2 shares for this test
        }
        let key_shares = execute_keygen(*share_count, *threshold);
        execute_sign_fault_r2_bad_proof(&key_shares, participant_indices, &MSG_TO_SIGN);
    }
}

fn execute_sign_fault_r2_bad_proof(
    key_shares: &[SecretKeyShare],
    participant_indices: &[usize],
    msg_to_sign: &[u8],
) {
    assert!(participant_indices.len() > 1);
    let (criminal, victim) = (1, 0);

    let mut participants: Vec<Sign> = participant_indices
        .iter()
        .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
        .collect();

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

    // corrupt the proof from party `criminal` to party `victim`
    let proof = &mut all_r1_p2ps[criminal].vec_ref_mut()[victim]
        .as_mut()
        .unwrap()
        .range_proof;
    *proof = corrupt_proof(proof);

    // deliver round 1 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r1p2ps = all_r1_p2ps.clone();
        participant.in_r1bcasts = all_r1_bcasts.clone();
    }

    // execute round 2 all participants and store their outputs
    let mut all_r2_p2ps = Vec::with_capacity(participants.len());
    let mut all_r2_bcasts_fail = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r2() {
            r2::Output::Success { state, out_p2ps } => {
                if i == victim {
                    panic!(
                        "r2 party {} expect failure but found success",
                        participant.my_secret_key_share.my_index
                    );
                }
                participant.r2state = Some(state);
                all_r2_p2ps.push(out_p2ps);
            }
            r2::Output::Fail { out_bcast } => {
                if i != victim {
                    panic!(
                        "r2 party {} expect success but found failure with culprits {:?}",
                        participant.my_secret_key_share.my_index, out_bcast.culprits
                    );
                }
                all_r2_bcasts_fail.insert(i, out_bcast).unwrap();
                all_r2_p2ps.push(FillVec::with_len(0)); // dummy TODO use FillVec instead of Vec?
            }
        }
    }

    // deliver round 2 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r2p2ps = all_r2_p2ps.clone();
        participant.in_r2bcasts_fail = all_r2_bcasts_fail.clone();

        // all participants transition to R2Fail because they all received at least one r2::FailBcast
        participant.status = Status::R2Fail;
    }

    // execute round 2 sad path all participants and store their outputs
    let mut all_culprit_lists = Vec::with_capacity(participants.len());
    for participant in participants.iter_mut() {
        let culprits = participant.r3fail();
        participant.status = Status::Fail;
        all_culprit_lists.push(culprits);
    }

    // TEST: everyone correctly computed the culprit list
    let actual_culprits: Vec<usize> = vec![criminal];
    for culprit_list in all_culprit_lists {
        assert_eq!(culprit_list, actual_culprits);
    }
}

#[test]
fn sign_fault_r2_false_accusation() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        if *share_count < 2 {
            continue; // need at least 2 shares for this test
        }
        let key_shares = execute_keygen(*share_count, *threshold);
        execute_sign_fault_r2_false_accusation(&key_shares, participant_indices, &MSG_TO_SIGN);
    }
}

fn execute_sign_fault_r2_false_accusation(
    key_shares: &[SecretKeyShare],
    participant_indices: &[usize],
    msg_to_sign: &[u8],
) {
    assert!(participant_indices.len() > 1);
    let (criminal_accuser, victim_accused) = (1, 0);

    let mut participants: Vec<Sign> = participant_indices
        .iter()
        .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
        .collect();

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
        participant.in_all_r1p2ps = all_r1_p2ps.clone();
        participant.in_r1bcasts = all_r1_bcasts.clone();
    }

    // execute round 2 all participants and store their outputs
    let mut all_r2_p2ps = Vec::with_capacity(participants.len());
    let mut all_r2_bcasts_fail = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r2() {
            r2::Output::Success { state, out_p2ps } => {
                // insert a false accusation by party 1 against party 0
                if i == criminal_accuser {
                    all_r2_bcasts_fail
                        .insert(
                            i,
                            r2::FailBcast {
                                culprits: vec![r2::Culprit {
                                    participant_index: victim_accused,
                                }],
                            },
                        )
                        .unwrap();
                    all_r2_p2ps.push(FillVec::with_len(0)); // dummy TODO use FillVec instead of Vec?
                } else {
                    participant.r2state = Some(state);
                    all_r2_p2ps.push(out_p2ps);
                }
            }
            r2::Output::Fail { out_bcast } => {
                panic!(
                    "r2 party {} expect success got failure with culprits: {:?}",
                    participant.my_secret_key_share.my_index, out_bcast
                );
            }
        }
    }

    // deliver round 2 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r2p2ps = all_r2_p2ps.clone();
        participant.in_r2bcasts_fail = all_r2_bcasts_fail.clone();

        // all participants transition to R2Fail because they all received at least one r2::FailBcast
        participant.status = Status::R2Fail;
    }

    // execute round 2 sad path all participants and store their outputs
    let mut all_culprit_lists = Vec::with_capacity(participants.len());
    for participant in participants.iter_mut() {
        let culprits = participant.r3fail();
        participant.status = Status::Fail;
        all_culprit_lists.push(culprits);
    }

    // TEST: everyone correctly computed the culprit list
    let actual_culprits: Vec<usize> = vec![criminal_accuser];
    for (i, culprit_list) in all_culprit_lists.iter().enumerate() {
        assert_eq!(
            culprit_list, &actual_culprits,
            "party {} unexpected culprit list",
            i
        );
    }
}
