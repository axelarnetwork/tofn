use std::convert::TryFrom;

use super::*;
use crate::{
    collections::{FillVecMap, HoleVecMap, Subset, TypedUsize, VecMap},
    gg20::{
        keygen::{tests::execute_keygen, KeygenPartyShareCounts, KeygenShareId, SecretKeyShare},
        sign::api::{new_sign, SignShareId},
    },
    sdk::implementer_api::{decode_message, deserialize, encode_message},
    sdk::{
        api::{BytesVec, Fault, Protocol, Round},
        implementer_api::{serialize, ExpectedMsgTypes, MsgType},
    },
};
use ecdsa::{elliptic_curve::sec1::ToEncodedPoint, hazmat::VerifyPrimitive};
use k256::{ecdsa::Signature, ProjectivePoint};
use tracing::debug;
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use crate::gg20::sign::malicious::Behaviour::Honest;

type Party = Round<BytesVec, SignShareId, SignPartyId, MAX_MSG_LEN>;
type Parties = Vec<Party>;
type PartyBcast = Result<VecMap<SignShareId, BytesVec>, ()>;
type PartyP2p = Result<VecMap<SignShareId, HoleVecMap<SignShareId, BytesVec>>, ()>;
type PartyResult = Result<BytesVec, FillVecMap<SignPartyId, Fault>>;
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

fn msg_to_sign() -> MessageDigest {
    let msg: &[u8] = &[
        42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    MessageDigest::try_from(msg).expect("could not convert msg to MessageDigest")
}

#[test]
#[traced_test]
fn basic_correctness() {
    let msg_to_sign = msg_to_sign();
    for test_case in test_case_list() {
        let key_shares = execute_keygen(&test_case.party_share_counts, test_case.threshold);
        execute_sign(key_shares, &test_case, &msg_to_sign);
    }
}

#[allow(non_snake_case, clippy::many_single_char_names)]
fn execute_sign(
    key_shares: VecMap<KeygenShareId, SecretKeyShare>,
    test_case: &TestCase,
    msg_to_sign: &MessageDigest,
) {
    debug!(
        "execute sign: total_share_count {}, threshold {}, sign_share_count {}",
        test_case.party_share_counts.total_share_count(),
        test_case.threshold,
        test_case.sign_share_count
    );

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
        VecMap::<TypedUsize<SignShareId>, TypedUsize<KeygenShareId>>::from_vec(
            test_case
                .party_share_counts
                .share_id_subset(&sign_parties)
                .unwrap(),
        );

    let r1_parties: Vec<_> = sign_parties_share_ids
        .iter()
        .map(|(_, &keygen_id)| {
            let key_share = key_shares.get(keygen_id).unwrap();

            match new_sign(
                key_share.group(),
                key_share.share(),
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

    // TEST: secret key shares yield the pubkey
    let x = r1_parties
        .iter()
        .map(|party| round_cast::<r2::R2>(party).w_i)
        .fold(k256::Scalar::zero(), |acc, w_i| acc + w_i);

    let y = ProjectivePoint::generator() * x;

    for (keygen_id, key_share) in &key_shares {
        assert_eq!(
            y,
            *key_share.group().y().as_ref(),
            "Share {} has invalid group public key",
            keygen_id
        );
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

    let (r3_parties, ..) = execute_round(r2_parties, 3, false, true);

    // TEST: MtA for delta_i, sigma_i
    let k_gamma = r3_parties
        .iter()
        .map(|party| {
            let r3_bcast: r3::BcastHappy = deserialize(
                &decode_message::<SignShareId>(party.bcast_out().unwrap())
                    .unwrap()
                    .payload,
            )
            .unwrap();
            *r3_bcast.delta_i.as_ref()
        })
        .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i);

    assert_eq!(k_gamma, k * gamma);

    let k_x = r3_parties
        .iter()
        .map(|party| round_cast::<r4::R4Happy>(party).sigma_i)
        .fold(k256::Scalar::zero(), |acc, sigma_i| acc + sigma_i);

    assert_eq!(k_x, k * x);

    let (r4_parties, ..) = execute_round(r3_parties, 4, true, false);

    // TEST: everyone correctly computed delta = k * gamma
    for party in &r4_parties {
        let delta_inv = round_cast::<r5::R5>(party).delta_inv;

        assert_eq!(delta_inv * k_gamma, k256::Scalar::one());
    }

    let (r5_parties, ..) = execute_round(r4_parties, 5, true, false);

    // TEST: everyone correctly computed R
    let R = k256::ProjectivePoint::generator() * k.invert().unwrap();
    for party in &r5_parties {
        let party_R = round_cast::<r6::R6>(party).R;

        assert_eq!(party_R, R);
    }

    let (r6_parties, ..) = execute_round(r5_parties, 6, true, true);

    let (r7_parties, ..) = execute_round(r6_parties, 7, true, false);

    let results = execute_final_round(r7_parties, 8, true, false);

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

#[test]
#[traced_test]
/// This unit test is now redundant.
/// It has been replicated as an integration test in `tests/integration/single_thread/malicious/sign_delta_inv.rs`.
fn malicious_delta_inverse() {
    let msg_to_sign = msg_to_sign();
    let test_case = TestCase {
        party_share_counts: KeygenPartyShareCounts::from_vec(vec![2, 2, 1]).unwrap(),
        threshold: 2,
        sign_share_count: 3,
    };
    let key_shares = execute_keygen(&test_case.party_share_counts, test_case.threshold);

    // `execute_sign` except with a rushing adversary in r4 to set delta = 0

    let mut sign_share_count = 0;
    let mut sign_parties = Subset::with_max_size(test_case.party_share_counts.party_count());
    for (i, _) in test_case.party_share_counts.iter() {
        sign_parties
            .add(TypedUsize::from_usize(i.as_usize()))
            .unwrap();

        sign_share_count += test_case.party_share_counts.party_share_count(i).unwrap();

        if sign_share_count > test_case.sign_share_count {
            break;
        }
    }

    let keygen_share_ids = VecMap::<TypedUsize<SignShareId>, TypedUsize<KeygenShareId>>::from_vec(
        test_case
            .party_share_counts
            .share_id_subset(&sign_parties)
            .unwrap(),
    );

    let r1_shares: Vec<_> = keygen_share_ids
        .iter()
        .map(|(_, &keygen_id)| {
            let key_share = key_shares.get(keygen_id).unwrap();

            match new_sign(
                key_share.group(),
                key_share.share(),
                &sign_parties,
                &msg_to_sign,
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

    let (r2_shares, ..) = execute_round(r1_shares, 2, true, true);

    let (mut r3_shares, ..) = execute_round(r2_shares, 3, false, true);

    // change the 0th share's `delta_i` so that sum_i delta_i = 0
    let delta_i_sum_except_0 = r3_shares
        .iter()
        .skip(1)
        .map(|party| {
            let r3_bcast: r3::BcastHappy = deserialize(
                &decode_message::<SignShareId>(party.bcast_out().unwrap())
                    .unwrap()
                    .payload,
            )
            .unwrap();
            *r3_bcast.delta_i.as_ref()
        })
        .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i);

    let share_0_bcast_out: r3::BcastHappy = deserialize(
        &decode_message::<SignShareId>(r3_shares[0].bcast_out().unwrap())
            .unwrap()
            .payload,
    )
    .unwrap();

    *r3_shares[0].bcast_out_mut() = Some(
        encode_message(
            serialize(&r3::BcastHappy {
                delta_i: delta_i_sum_except_0.negate().into(),
                ..share_0_bcast_out
            })
            .unwrap(),
            TypedUsize::<SignShareId>::from_usize(0),
            MsgType::Bcast,
            ExpectedMsgTypes::BcastOnly,
        )
        .unwrap(),
    );

    // sanity check: delta == 0?
    assert_eq!(
        r3_shares
            .iter()
            .map(|share| {
                let r3_bcast: r3::BcastHappy = deserialize(
                    &decode_message::<SignShareId>(share.bcast_out().unwrap())
                        .unwrap()
                        .payload,
                )
                .unwrap();
                *r3_bcast.delta_i.as_ref()
            })
            .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i),
        k256::Scalar::zero()
    );

    let (r4_shares, ..) = execute_round(r3_shares, 4, true, false);

    // we should now be in round 5 'type 5' sad path
    let result_shares = execute_final_round(r4_shares, 5, true, true);

    // TEST: honest shares (ie. everyone except the 0th share) correctly computed the faulters list
    let mut expected_faulters = FillVecMap::with_size(sign_parties.member_count());
    expected_faulters
        .set(TypedUsize::from_usize(0), Fault::ProtocolFault)
        .unwrap();
    for result in result_shares.into_iter().skip(1) {
        let faulters =
            result.expect_err("honest sign share_id {} protocol success, expect failure");
        assert_eq!(faulters, expected_faulters);
    }
}

fn round_cast<T: 'static>(party: &Party) -> &T {
    return party.round_as_any().downcast_ref::<T>().unwrap();
}

fn execute_round(
    mut parties: Parties,
    round_num: usize,
    expect_bcast_in: bool,
    expect_p2p_in: bool,
) -> (Parties, PartyBcast, PartyP2p) {
    debug!("execute round {}", round_num);

    // Special case: total_share_count == 1 and expected_msg_types == P2pOnly
    // In this case we should expect a bcast indicating P2pOnly
    let expect_bcast_in = if parties.len() == 1 && !expect_bcast_in && expect_p2p_in {
        debug!("special case in round {}: total_share_count 1 and P2psOnly: look for bcast TotalShareCount1P2pOnly", round_num);
        true
    } else {
        expect_bcast_in
    };

    let bcasts = retrieve_and_set_bcasts(&mut parties, expect_bcast_in, round_num);
    let p2ps = retrieve_and_set_p2ps(&mut parties, expect_p2p_in, round_num);

    let next_round_parties: Parties = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(!party.expecting_more_msgs_this_round());
            assert_eq!(party.bcast_out().is_some(), expect_bcast_in);
            assert_eq!(party.p2ps_out().is_some(), expect_p2p_in);

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
            round
        })
        .collect();

    (next_round_parties, bcasts, p2ps)
}

fn execute_final_round(
    mut parties: Parties,
    round_num: usize,
    expect_bcast_in: bool,
    expect_p2p_in: bool,
) -> Vec<PartyResult> {
    let _bcasts = retrieve_and_set_bcasts(&mut parties, expect_bcast_in, round_num);
    let _p2ps = retrieve_and_set_p2ps(&mut parties, expect_p2p_in, round_num);

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

    let bcasts: VecMap<SignShareId, _> = parties
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

    let all_p2ps: VecMap<SignShareId, _> = parties
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
