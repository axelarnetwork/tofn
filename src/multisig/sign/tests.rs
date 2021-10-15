use std::convert::TryFrom;

use super::*;
use crate::{
    collections::{FillVecMap, HoleVecMap, Subset, TypedUsize, VecMap},
    multisig::{
        keygen::{tests::execute_keygen, KeygenPartyShareCounts, KeygenShareId, SecretKeyShare},
        sign::api::{new_sign, SignShareId},
    },
    sdk::api::{BytesVec, Fault, Protocol, Round},
};
use ecdsa::hazmat::VerifyPrimitive;
use tracing::debug;
use tracing_test::traced_test;

type Party = Round<SignProtocolOutput, SignShareId, SignPartyId, MAX_MSG_LEN>;
type Parties = Vec<Party>;
type PartyBcast = Result<VecMap<SignShareId, BytesVec>, ()>;
type PartyP2p = Result<VecMap<SignShareId, HoleVecMap<SignShareId, BytesVec>>, ()>;
type PartyResult = Result<SignProtocolOutput, FillVecMap<SignPartyId, Fault>>;
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
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![10, 2, 3]).unwrap(),
            threshold: 3,
            sign_share_count: 12,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![3, 2, 1]).unwrap(),
            threshold: 5,
            sign_share_count: 6,
        },
    ]
}

fn msg_to_sign() -> MessageDigest {
    let msg: &[u8] = &[42; 32];
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

    let sign_parties_share_ids = VecMap::<SignShareId, TypedUsize<KeygenShareId>>::from_vec(
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
            )
            .unwrap()
            {
                Protocol::NotDone(round) => round,
                Protocol::Done(_) => panic!("`new_sign` returned a `Done` protocol"),
            }
        })
        .collect();

    let results = execute_final_round(r1_parties, 2, true, false);
    let results: VecMap<SignShareId, _> = results.into_iter().map(Result::unwrap).collect();

    // test: consensus on sigs
    let all_sig_shares = results.get(TypedUsize::from_usize(0)).unwrap();
    assert_eq!(all_sig_shares.len(), test_case.threshold + 1);
    for (_, sigs) in results.iter().skip(1) {
        assert_eq!(sigs, all_sig_shares);
    }

    // TEST: verify all sigs
    let all_verifying_keys = key_shares.iter().next().unwrap().1.group().all_pubkeys();
    let hashed_msg = k256::Scalar::from(msg_to_sign);

    for sig_share in all_sig_shares {
        let keygen_id = test_case
            .party_share_counts
            .party_to_share_id(sig_share.party_id, sig_share.subshare_id)
            .unwrap();
        let verifying_key = all_verifying_keys
            .get(keygen_id)
            .unwrap()
            .as_ref()
            .to_affine();
        let signature = k256::ecdsa::Signature::from_der(&sig_share.signature_bytes).unwrap();
        verifying_key
            .verify_prehashed(&hashed_msg, &signature)
            .unwrap();
    }
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
