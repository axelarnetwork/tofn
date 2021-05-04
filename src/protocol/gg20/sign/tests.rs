use super::*;
use crate::protocol::{
    gg20::keygen::{self, SecretKeyShare},
    gg20::tests::sign::{MSG_TO_SIGN, TEST_CASES},
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use k256::{
    ecdsa::{Asn1Signature, Signature},
    FieldBytes,
};
use keygen::tests::execute_keygen;
use tracing_test::traced_test; // enable logs in tests

#[test]
#[traced_test]
fn basic_correctness() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        let key_shares = execute_keygen(*share_count, *threshold);
        basic_correctness_inner(&key_shares, participant_indices, &MSG_TO_SIGN);
    }
}

fn basic_correctness_inner(
    key_shares: &[SecretKeyShare],
    participant_indices: &[usize],
    msg_to_sign: &[u8],
) {
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
    assert_eq!(all_r1_p2ps.len(), participants.len());

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
    assert_eq!(all_r2_p2ps.len(), participants.len());

    // deliver round 2 msgs
    for participant in participants.iter_mut() {
        participant.in_all_r2p2ps = all_r2_p2ps.clone();
    }

    // execute round 3 all participants and store their outputs
    let mut all_r3_bcasts = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r3() {
            r3::Output::Success { state, out_bcast } => {
                participant.r3state = Some(state);
                participant.status = Status::R3;
                all_r3_bcasts.insert(i, out_bcast).unwrap();
            }
            r3::Output::Fail { out_bcast } => {
                panic!(
                    "r3 party {} expect success got failure with culprits: {:?}",
                    participant.my_secret_key_share.my_index, out_bcast
                );
            }
        }
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
        match participant.r4() {
            r4::Output::Success { state, out_bcast } => {
                participant.r4state = Some(state);
                participant.status = Status::R4;
                all_r4_bcasts.insert(i, out_bcast).unwrap();
            }
            r4::Output::Fail { criminals } => {
                panic!(
                    "r4 party {} expect success got failure with criminals: {:?}",
                    participant.my_secret_key_share.my_index, criminals
                );
            }
        }
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
        match participant.r5() {
            r5::Output::Success {
                state,
                out_bcast,
                out_p2ps,
            } => {
                participant.r5state = Some(state);
                participant.status = Status::R5;
                all_r5_bcasts.insert(i, out_bcast).unwrap();
                all_r5_p2ps.push(out_p2ps);
            }
            r5::Output::Fail { criminals } => {
                panic!(
                    "r5 party {} expect success got failure with criminals: {:?}",
                    participant.my_secret_key_share.my_index, criminals
                );
            }
        }
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
        match participant.r6() {
            r6::Output::Success { state, out_bcast } => {
                participant.r6state = Some(state);
                participant.status = Status::R6;
                all_r6_bcasts.insert(i, out_bcast).unwrap();
            }
            r6::Output::Fail { out_bcast } => {
                panic!(
                    "r6 party {} expect success got failure with culprits: {:?}",
                    participant.my_secret_key_share.my_index, out_bcast
                );
            }
            r6::Output::FailType5 { out_bcast: _ } => {
                panic!(
                    "r6 party {} expect success got kicked into R6FailRandomizer mode",
                    participant.my_secret_key_share.my_index
                );
            }
        }
    }

    // deliver round 6 msgs
    for participant in participants.iter_mut() {
        participant.in_r6bcasts = all_r6_bcasts.clone();
    }

    // execute round 7 all participants and store their outputs
    let mut all_r7_bcasts = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r7() {
            r7::Output::Success { state, out_bcast } => {
                participant.r7state = Some(state);
                participant.status = Status::R7;
                all_r7_bcasts.insert(i, out_bcast).unwrap();
            }
            r7::Output::Fail { criminals } => {
                panic!(
                    "r7 party {} expect success got failure with criminals: {:?}",
                    participant.my_secret_key_share.my_index, criminals
                );
            }
        }
    }

    // deliver round 7 msgs
    for participant in participants.iter_mut() {
        participant.in_r7bcasts = all_r7_bcasts.clone();
    }

    // execute round 8 all participants and store their outputs
    let mut all_sigs = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        let sig = match participant.r8() {
            r8::Output::Success { sig } => sig,
            r8::Output::Fail { criminals } => {
                panic!(
                    "r8 party {} expect success got failure with criminals: {:?}",
                    participant.my_secret_key_share.my_index, criminals
                );
            }
        };
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
    for sig in all_sigs.vec_ref().iter() {
        let (sig_r, sig_s) = extract_r_s(sig.as_ref().unwrap());
        let (sig_r, sig_s) = (sig_r.as_slice(), sig_s.as_slice());
        let (sig_r, sig_s): (BigInt, BigInt) = (BigInt::from(sig_r), BigInt::from(sig_s));
        assert_eq!(sig_r, r.to_big_int());
        assert_eq!(sig_s, s.to_big_int());
    }

    let sig = EcdsaSig { r, s };
    assert!(sig.verify(&ecdsa_public_key, &msg_to_sign));
}

fn extract_r_s(asn1_sig: &Asn1Signature) -> (FieldBytes, FieldBytes) {
    let sig = Signature::from_asn1(asn1_sig.as_bytes()).unwrap();
    let (sig_r, sig_s) = (sig.r(), sig.s());
    (From::from(sig_r), From::from(sig_s))
}
