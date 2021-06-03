use super::*;
use crate::protocol::{
    gg20::keygen::{self, SecretKeyShare},
    gg20::tests::sign::{MSG_TO_SIGN, TEST_CASES},
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use ecdsa::{elliptic_curve::sec1::ToEncodedPoint, hazmat::VerifyPrimitive};
use k256::{
    ecdsa::{DerSignature, Signature},
    FieldBytes,
};
use keygen::tests::execute_keygen;
use tracing::debug;
use tracing_test::traced_test; // enable logs in tests

#[test]
#[traced_test]
fn basic_correctness() {
    for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
        debug!(
            "test case: share_count {}, threshold {}, participants: {:?}",
            share_count, threshold, participant_indices
        );
        let key_shares = execute_keygen(*share_count, *threshold);
        basic_correctness_inner(&key_shares, participant_indices, &MSG_TO_SIGN);
    }
}

#[allow(non_snake_case)]
fn basic_correctness_inner(
    key_shares: &[SecretKeyShare],
    participant_indices: &[usize],
    msg_to_sign: &[u8; 32],
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

    // curv: TEST: secret key shares yield the pubkey
    let x = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().w_i)
        .fold(FE::zero(), |acc, w_i| acc + w_i);
    let y = GE::generator() * x;
    for key_share in key_shares.iter() {
        assert_eq!(y, key_share.ecdsa_public_key);
    }

    // k256: TEST: secret key shares yield the pubkey
    let x_k256 = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().w_i_k256)
        .fold(k256::Scalar::zero(), |acc, w_i| acc + w_i);
    let y_k256 = k256::ProjectivePoint::generator() * x_k256;
    for key_share in key_shares.iter() {
        assert_eq!(y_k256, *key_share.y_k256.unwrap());
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

    // curv: TEST: MtA for delta_i, sigma_i
    let k = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().k_i)
        .fold(FE::zero(), |acc, x| acc + x);
    let gamma = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().gamma_i)
        .fold(FE::zero(), |acc, x| acc + x);
    let k_gamma = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().delta_i)
        .fold(FE::zero(), |acc, x| acc + x);
    assert_eq!(k_gamma, k * gamma);
    let k_x = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().sigma_i)
        .fold(FE::zero(), |acc, x| acc + x);
    assert_eq!(k_x, k * x);

    // k256: TEST: MtA for delta_i, sigma_i
    let k_k256 = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().k_i_k256)
        .fold(k256::Scalar::zero(), |acc, x| acc + x);
    let gamma_k256 = participants
        .iter()
        .map(|p| p.r1state.as_ref().unwrap().gamma_i_k256)
        .fold(k256::Scalar::zero(), |acc, x| acc + x);
    let k_gamma_k256 = participants
        .iter()
        .map(|p| {
            p.in_r3bcasts.vec_ref()[p.my_participant_index]
                .as_ref()
                .unwrap()
                .delta_i_k256
                .unwrap()
        })
        .fold(k256::Scalar::zero(), |acc, x| acc + x);
    assert_eq!(k_gamma_k256, k_k256 * gamma_k256);
    let k_x_k256 = participants
        .iter()
        .map(|p| p.r3state.as_ref().unwrap().sigma_i_k256)
        .fold(k256::Scalar::zero(), |acc, x| acc + x);
    assert_eq!(k_x_k256, k_k256 * x_k256);

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

    // curv: TEST: everyone correctly computed nonce_x_blind (delta = k*gamma)
    for delta_inv in participants
        .iter()
        .map(|p| p.r4state.as_ref().unwrap().delta_inv)
    {
        assert_eq!(delta_inv * k_gamma, one);
    }

    // k256: TEST: everyone correctly computed delta = k * gamma
    for delta_inv_k256 in participants
        .iter()
        .map(|p| p.r4state.as_ref().unwrap().delta_inv_k256)
    {
        assert_eq!(delta_inv_k256 * k_gamma_k256, k256::Scalar::one());
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

    // k256: TEST: everyone correctly computed R
    let R_k256 = k256::ProjectivePoint::generator() * k_k256.invert().unwrap();
    for participant_R_k256 in participants
        .iter()
        .map(|p| p.r5state.as_ref().unwrap().R_k256)
    {
        assert_eq!(participant_R_k256, R_k256);
    }

    // execute round 6 all participants and store their outputs
    let mut all_r6_bcasts = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r6() {
            r6::Output::Success { out_bcast } => {
                participant.status = Status::R6;
                all_r6_bcasts.insert(i, out_bcast).unwrap();
            }
            r6_output => {
                panic!(
                    "r6 party {} expect success got failure {:?}",
                    participant.my_secret_key_share.my_index, r6_output
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
            r7_output => {
                panic!(
                    "r7 party {} expect success got failure {:?}",
                    participant.my_secret_key_share.my_index, r7_output
                );
            }
        }
    }

    // deliver round 7 msgs
    for participant in participants.iter_mut() {
        participant.in_r7bcasts = all_r7_bcasts.clone();
    }

    // execute round 8 all participants and store their outputs
    let mut all_sigs_k256 = FillVec::with_len(participants.len());
    for (i, participant) in participants.iter_mut().enumerate() {
        match participant.r8() {
            r8::Output::Success { sig_k256 } => {
                all_sigs_k256.insert(i, sig_k256).unwrap();
            }
            r8::Output::Fail { criminals } => {
                panic!(
                    "r8 party {} expect success got failure with criminals: {:?}",
                    participant.my_secret_key_share.my_index, criminals
                );
            }
        };
        participant.status = Status::Done;
    }

    // k256: TEST: everyone correctly computed the signature
    let msg_to_sign_k256 =
        k256::Scalar::from_bytes_reduced(k256::FieldBytes::from_slice(&msg_to_sign[..]));
    let r_k256 =
        k256::Scalar::from_bytes_reduced(R_k256.to_affine().to_encoded_point(true).x().unwrap());
    let s_k256 = k_k256 * (msg_to_sign_k256 + x_k256 * r_k256);
    let sig_k256 = {
        let mut sig_k256 = Signature::from_scalars(r_k256, s_k256).unwrap();
        sig_k256.normalize_s().unwrap();
        sig_k256
    };
    for participant_sig_k256 in all_sigs_k256.vec_ref().iter() {
        assert_eq!(
            Signature::from_der(participant_sig_k256.as_ref().unwrap().as_bytes()).unwrap(),
            sig_k256
        );
    }

    // k256: TEST: the signature verifies
    let verifying_key_k256 = y_k256.to_affine();
    assert!(verifying_key_k256
        .verify_prehashed(&msg_to_sign_k256, &sig_k256)
        .is_ok());
}

fn extract_r_s(asn1_sig: &DerSignature) -> (FieldBytes, FieldBytes) {
    let sig = Signature::from_der(asn1_sig.as_bytes()).unwrap();
    let (sig_r, sig_s) = (sig.r(), sig.s());
    (From::from(sig_r), From::from(sig_s))
}
