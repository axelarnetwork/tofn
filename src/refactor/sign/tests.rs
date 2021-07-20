use std::convert::TryFrom;

use super::*;
use crate::{
    refactor::{
        collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
        keygen::tests::{execute_keygen, TEST_CASES},
        protocol::api::{Fault, Round},
    },
    refactor::{
        keygen::{tests::TestCase, KeygenPartyIndex, SecretKeyShare},
        protocol::api::{BytesVec, Protocol},
        sign::api::{new_sign, SignParticipantIndex},
    },
};
use bincode::deserialize;
use ecdsa::{elliptic_curve::sec1::ToEncodedPoint, hazmat::VerifyPrimitive};
use k256::{ecdsa::Signature, ProjectivePoint};
use tracing::debug;
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use crate::refactor::sign::malicious::Behaviour::Honest;

type Parties = Vec<Round<BytesVec, SignParticipantIndex>>;
type PartyBcast = Result<VecMap<SignParticipantIndex, BytesVec>, ()>;
type PartyP2p =
    Result<VecMap<SignParticipantIndex, HoleVecMap<SignParticipantIndex, BytesVec>>, ()>;
type PartyResult = Result<BytesVec, FillVecMap<SignParticipantIndex, Fault>>;

#[test]
#[traced_test]
fn basic_correctness() {
    let msg: &[u8] = &[
        42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let msg_to_sign: MessageDigest =
        MessageDigest::try_from(msg).expect("could not convert msg to MessageDigest");

    for t in TEST_CASES.iter() {
        let key_shares = execute_keygen(t.share_count, t.threshold);

        execute_sign(key_shares, t, &msg_to_sign);
    }
}

#[allow(non_snake_case, clippy::many_single_char_names)]
fn execute_sign(
    key_shares: Vec<SecretKeyShare>,
    test_case: &TestCase,
    msg_to_sign: &MessageDigest,
) {
    let everyone = VecMap::<SignParticipantIndex, TypedUsize<KeygenPartyIndex>>::from_vec(
        (0..test_case.threshold + 1)
            .map(TypedUsize::<KeygenPartyIndex>::from_usize)
            .collect::<Vec<_>>(),
    );

    let key_shares: Vec<_> = everyone
        .iter()
        .map(|(sign_peer_id, _)| key_shares[sign_peer_id.as_usize()].clone())
        .collect();

    let r0_parties: Vec<_> = key_shares
        .iter()
        .map(|key_share| {
            match new_sign(
                &key_share.group,
                &key_share.share,
                &everyone,
                msg_to_sign,
                #[cfg(feature = "malicious")]
                Honest,
            )
            .unwrap()
            {
                Protocol::NotDone(round) => round,
                Protocol::Done(_) => panic!("`new_sign` returned a `Done` protocol"),
            }
        })
        .collect();

    // execute round 1 all parties
    let (r1_parties, ..) = execute_round(r0_parties, 1, true, true);

    // TEST: secret key shares yield the pubkey
    let x = r1_parties
        .iter()
        .map(|party| round_cast::<r2::R2>(party).w_i)
        .fold(k256::Scalar::zero(), |acc, w_i| acc + w_i);

    let y = ProjectivePoint::generator() * x;

    for key_share in &key_shares {
        assert_eq!(y, *key_share.group.y.unwrap());
    }

    let k = r1_parties
        .iter()
        .map(|party| round_cast::<r2::R2>(party).k_i)
        .fold(k256::Scalar::zero(), |acc, k_i| acc + k_i);

    let gamma = r1_parties
        .iter()
        .map(|party| round_cast::<r2::R2>(party).gamma_i)
        .fold(k256::Scalar::zero(), |acc, gamma_i| acc + gamma_i);

    let (r2_parties, ..) = execute_round(r1_parties, 2, true, true);

    let (r3_parties, r3bcasts, ..) = execute_round(r2_parties, 3, true, false);
    let r3bcasts = r3bcasts.expect("missing r3 bcasts");

    // TEST: MtA for delta_i, sigma_i
    let k_gamma = r3bcasts
        .iter()
        .map(|(_, bytes)| {
            let bcast: r3::Bcast = deserialize(bytes).expect("failed to deserialize r3 bcast");
            *bcast.delta_i.unwrap()
        })
        .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i);

    assert_eq!(k_gamma, k * gamma);

    let k_x = r3_parties
        .iter()
        .map(|party| round_cast::<r4::R4>(party).sigma_i)
        .fold(k256::Scalar::zero(), |acc, sigma_i| acc + sigma_i);

    assert_eq!(k_x, k * x);

    let (r4_parties, ..) = execute_round(r3_parties, 4, true, false);

    // TEST: everyone correctly computed delta = k * gamma
    for party in &r4_parties {
        let delta_inv = round_cast::<r5::R5>(party).delta_inv;

        assert_eq!(delta_inv * k_gamma, k256::Scalar::one());
    }

    let (r5_parties, ..) = execute_round(r4_parties, 5, true, true);

    // TEST: everyone correctly computed R
    let R = k256::ProjectivePoint::generator() * k.invert().unwrap();
    for party in &r5_parties {
        let party_R = round_cast::<r6::R6>(party).R;

        assert_eq!(party_R, R);
    }

    let (r6_parties, ..) = execute_round(r5_parties, 6, true, false);

    let (r7_parties, ..) = execute_round(r6_parties, 7, true, false);

    let results = execute_final_round(r7_parties, 8);

    // TEST: everyone correctly computed the signature using non-threshold ECDSA sign
    let m: k256::Scalar = msg_to_sign.into();
    let r = k256::Scalar::from_bytes_reduced(R.to_affine().to_encoded_point(true).x().unwrap());
    let s = k * (m + x * r);

    let sig = {
        let mut sig = Signature::from_scalars(r, s).unwrap();
        sig.normalize_s().unwrap();
        sig
    };
    let encoded_sig = sig.to_der().as_bytes().to_vec();

    for result in results {
        let encoded_threshold_sig = result.expect("round 8 signature computation failed");
        let threshold_sig =
            Signature::from_der(&encoded_threshold_sig).expect("decoding threshold sig failed");

        assert_eq!(threshold_sig, sig);
        assert_eq!(encoded_threshold_sig, encoded_sig);
    }

    // TEST: signature verification
    let pub_key = y.to_affine();
    assert!(pub_key.verify_prehashed(&m, &sig).is_ok());
}

fn round_cast<T: 'static>(party: &Round<BytesVec, SignParticipantIndex>) -> &T {
    return party.round_as_any().downcast_ref::<T>().unwrap();
}

fn execute_round(
    parties: Parties,
    round_num: usize,
    expect_bcast_out: bool,
    expect_p2p_out: bool,
) -> (Parties, PartyBcast, PartyP2p) {
    let mut next_round_parties: Parties = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(!party.expecting_more_msgs_this_round());
            let round = match party
                .execute_next_round()
                .expect("Encountered protocol fault")
            {
                Protocol::NotDone(next_round) => next_round,
                Protocol::Done(_) => panic!(
                    "party {} done after round {}, expected not done",
                    i, round_num
                ),
            };

            assert_eq!(round.bcast_out().is_some(), expect_bcast_out);
            assert_eq!(round.p2ps_out().is_some(), expect_p2p_out);

            round
        })
        .collect();

    let bcasts = retrieve_and_set_bcasts(&mut next_round_parties, expect_bcast_out, round_num);
    let p2ps = retrieve_and_set_p2ps(&mut next_round_parties, expect_p2p_out, round_num);

    (next_round_parties, bcasts, p2ps)
}

fn execute_final_round(parties: Parties, round_num: usize) -> Vec<PartyResult> {
    let mut results = Vec::new();

    debug!("Executing the final round");

    for (i, party) in parties.into_iter().enumerate() {
        assert!(!party.expecting_more_msgs_this_round());
        let res = match party.execute_next_round().unwrap() {
            Protocol::Done(res) => res,
            Protocol::NotDone(_) => panic!(
                "party {} not done after round {}, expected done",
                i, round_num
            ),
        };

        results.push(res);
    }

    results
}

fn retrieve_and_set_bcasts(
    parties: &mut Parties,
    expect_bcast: bool,
    round_num: usize,
) -> PartyBcast {
    if !expect_bcast {
        return Err(());
    }

    debug!("Round {}: broadcasting messages for next round", round_num);

    let bcasts: VecMap<SignParticipantIndex, BytesVec> = parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in parties.iter_mut() {
        for (from, bytes) in bcasts.iter() {
            party.bcast_in(from, bytes).unwrap();
        }
    }

    Ok(bcasts)
}

fn retrieve_and_set_p2ps(parties: &mut Parties, expect_p2p: bool, round_num: usize) -> PartyP2p {
    if !expect_p2p {
        return Err(());
    }

    debug!("Round {}: sending p2p messages for next round", round_num);

    let all_p2ps: VecMap<SignParticipantIndex, HoleVecMap<SignParticipantIndex, BytesVec>> =
        parties
            .iter()
            .map(|party| party.p2ps_out().unwrap().clone())
            .collect();

    for party in parties.iter_mut() {
        for (from, p2ps) in all_p2ps.iter() {
            for (to, msg) in p2ps.iter() {
                party.p2p_in(from, to, msg).unwrap();
            }
        }
    }

    Ok(all_p2ps)
}
