use std::convert::TryFrom;

use super::*;
use crate::{
    gg20::{
        keygen::{tests::execute_keygen, KeygenPartyIndex, KeygenPartyShareCounts, SecretKeyShare},
        sign::api::{new_sign, SignParticipantIndex},
    },
    refactor::{
        collections::Subset,
        sdk::api::{BytesVec, Protocol},
    },
    refactor::{
        collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
        sdk::api::{Fault, Round},
    },
};
use ecdsa::{elliptic_curve::sec1::ToEncodedPoint, hazmat::VerifyPrimitive};
use k256::{ecdsa::Signature, ProjectivePoint};
use tracing::debug;
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use crate::gg20::sign::malicious::Behaviour::Honest;

type Party = Round<BytesVec, SignParticipantIndex, RealSignParticipantIndex>;
type Parties = Vec<Party>;
type PartyBcast = Result<VecMap<SignParticipantIndex, BytesVec>, ()>;
type PartyP2p =
    Result<VecMap<SignParticipantIndex, HoleVecMap<SignParticipantIndex, BytesVec>>, ()>;
type PartyResult = Result<BytesVec, FillVecMap<RealSignParticipantIndex, Fault>>;
struct TestCase {
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    sign_share_count: usize,
}

fn test_case_list() -> Vec<TestCase> {
    vec![
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![1]).unwrap(),
            threshold: 0,
            sign_share_count: 1,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![5]).unwrap(),
            threshold: 0,
            sign_share_count: 5,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![1, 1, 1]).unwrap(),
            threshold: 1,
            sign_share_count: 2,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![0, 0, 2]).unwrap(),
            threshold: 1,
            sign_share_count: 2,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![2, 0, 3, 1]).unwrap(),
            threshold: 3,
            sign_share_count: 4,
        },
        // TestCase {
        //     party_share_counts: KeygenPartyShareCounts::from_vec(vec![10, 2, 3]).unwrap(),
        //     threshold: 3,
        //     sign_share_count: 12,
        // },
        // TestCase {
        //     party_share_counts: KeygenPartyShareCounts::from_vec(vec![3, 2, 1]).unwrap(),
        //     threshold: 5,
        //     sign_share_count: 6,
        // },
    ]
}

#[test]
#[traced_test]
fn basic_correctness() {
    let msg: &[u8] = &[
        42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let msg_to_sign: MessageDigest =
        MessageDigest::try_from(msg).expect("could not convert msg to MessageDigest");

    for test_case in test_case_list() {
        let key_shares = execute_keygen(&test_case.party_share_counts, test_case.threshold);

        execute_sign(key_shares, &test_case, &msg_to_sign);
    }
}

#[allow(non_snake_case, clippy::many_single_char_names)]
fn execute_sign(
    key_shares: Vec<SecretKeyShare>,
    test_case: &TestCase,
    msg_to_sign: &MessageDigest,
) {
    let mut share_count = 0;
    let mut sign_parties = Subset::with_max_size(test_case.party_share_counts.party_count());
    for (i, _) in test_case.party_share_counts.iter() {
        sign_parties
            .add(TypedUsize::from_usize(i.as_usize()))
            .unwrap();

        share_count += test_case.party_share_counts.party_share_count(i).unwrap();

        if share_count > test_case.sign_share_count {
            break;
        }
    }

    let sign_parties_share_ids =
        VecMap::<TypedUsize<SignParticipantIndex>, TypedUsize<KeygenPartyIndex>>::from_vec(
            test_case
                .party_share_counts
                .share_id_subset(&sign_parties)
                .unwrap(),
        );

    let r0_parties: Vec<_> = sign_parties_share_ids
        .iter()
        .map(|(_, &keygen_id)| {
            let key_share = key_shares.get(keygen_id.as_usize()).unwrap();

            match new_sign(
                &key_share.group(),
                &key_share.share(),
                &sign_parties,
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
        assert_eq!(y, *key_share.group().y().unwrap());
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

    let (r3_parties, ..) = execute_round(r2_parties, 3, true, false);

    // TEST: MtA for delta_i, sigma_i
    let k_gamma = r3_parties
        .iter()
        .map(|party| round_cast::<r4::happy::R4>(party)._delta_i)
        .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i);

    assert_eq!(k_gamma, k * gamma);

    let k_x = r3_parties
        .iter()
        .map(|party| round_cast::<r4::happy::R4>(party).sigma_i)
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
        let encoded_threshold_sig = result
            .map_err(|_| ())
            .expect("round 8 signature computation failed");
        let threshold_sig =
            Signature::from_der(&encoded_threshold_sig).expect("decoding threshold sig failed");

        assert_eq!(threshold_sig, sig);
        assert_eq!(encoded_threshold_sig, encoded_sig);
    }

    // TEST: signature verification
    let pub_key = y.to_affine();
    assert!(pub_key.verify_prehashed(&m, &sig).is_ok());
}

fn round_cast<T: 'static>(party: &Party) -> &T {
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

    let bcasts: VecMap<SignParticipantIndex, _> = parties
        .iter()
        .map(|party| (party.info().party_id(), party.bcast_out().unwrap().clone()))
        .collect();

    for party in parties.iter_mut() {
        for (_, (from, bytes)) in bcasts.iter() {
            party.msg_in(*from, bytes).unwrap();
        }
    }

    Ok(bcasts.into_iter().map(|(_, (_, bcast))| bcast).collect())
}

fn retrieve_and_set_p2ps(parties: &mut Parties, expect_p2p: bool, round_num: usize) -> PartyP2p {
    if !expect_p2p {
        return Err(());
    }

    debug!("Round {}: sending p2p messages for next round", round_num);

    let all_p2ps: VecMap<SignParticipantIndex, _> = parties
        .iter()
        .map(|party| (party.info().party_id(), party.p2ps_out().unwrap().clone()))
        .collect();

    for party in parties.iter_mut() {
        for (_, (from, p2ps)) in all_p2ps.iter() {
            for (_, msg) in p2ps.iter() {
                party.msg_in(*from, msg).unwrap();
            }
        }
    }

    Ok(all_p2ps.into_iter().map(|(_, (_, msg))| msg).collect())
}
