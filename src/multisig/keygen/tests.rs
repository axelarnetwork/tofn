use super::{secret_key_share::SecretKeyShare, *};
use crate::{
    collections::VecMap,
    crypto_tools::rng::{dummy_secret_recovery_key, SecretRecoveryKey},
    sdk::api::{BytesVec, Protocol},
};
use tracing_test::traced_test;

#[test]
#[traced_test]
fn basic_correctness() {
    for t in test_case_list() {
        execute_keygen(&t.party_share_counts, t.threshold);
    }
}

struct TestCase {
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
}

fn test_case_list() -> Vec<TestCase> {
    vec![
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![2, 0, 2]).unwrap(),
            threshold: 3,
        },
        TestCase {
            party_share_counts: KeygenPartyShareCounts::from_vec(vec![10, 2, 3]).unwrap(),
            threshold: 3,
        },
    ]
}

pub fn execute_keygen(
    party_share_counts: &KeygenPartyShareCounts,
    threshold: usize,
) -> VecMap<KeygenShareId, SecretKeyShare> {
    execute_keygen_with_recovery(party_share_counts, threshold).shares
}

pub struct KeySharesWithRecovery {
    pub shares: VecMap<KeygenShareId, SecretKeyShare>,
    pub secret_recovery_keys: VecMap<KeygenPartyId, SecretRecoveryKey>,
    pub session_nonce: Vec<u8>,
}

fn execute_keygen_with_recovery(
    party_share_counts: &KeygenPartyShareCounts,
    threshold: usize,
) -> KeySharesWithRecovery {
    let secret_recovery_keys = VecMap::from_vec(
        (0..party_share_counts.party_count())
            .map(dummy_secret_recovery_key)
            .collect(),
    );
    let session_nonce = b"foobar".to_vec();

    KeySharesWithRecovery {
        shares: execute_keygen_from_recovery(
            party_share_counts,
            threshold,
            &secret_recovery_keys,
            &session_nonce,
        ),
        secret_recovery_keys,
        session_nonce,
    }
}

fn execute_keygen_from_recovery(
    party_share_counts: &KeygenPartyShareCounts,
    threshold: usize,
    secret_recovery_keys: &VecMap<KeygenPartyId, SecretRecoveryKey>,
    session_nonce: &[u8],
) -> VecMap<KeygenShareId, SecretKeyShare> {
    assert_eq!(secret_recovery_keys.len(), party_share_counts.party_count());

    let mut r1_parties: Vec<_> = party_share_counts
        .iter()
        .map(|(party_id, &party_share_count)| {
            (0..party_share_count).map(move |subshare_id| {
                // each party use the same secret recovery key for all its subshares
                match new_keygen(
                    party_share_counts.clone(),
                    threshold,
                    party_id,
                    subshare_id,
                    secret_recovery_keys.get(party_id).unwrap(),
                    session_nonce,
                )
                .unwrap()
                {
                    Protocol::NotDone(round) => round,
                    Protocol::Done(_) => panic!("`new_keygen` returned a `Done` protocol"),
                }
            })
        })
        .flatten()
        .collect();

    // deliver r1 messages
    let r1_bcasts: VecMap<KeygenShareId, BytesVec> = r1_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r1_parties.iter_mut() {
        for (from, bytes) in r1_bcasts.iter() {
            party
                .msg_in(party_share_counts.share_to_party_id(from).unwrap(), bytes)
                .unwrap();
        }
    }

    // execute round 2 all parties
    let all_secret_key_shares: VecMap<KeygenShareId, SecretKeyShare> = r1_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.bcast_out().is_some());
            assert!(party.p2ps_out().is_none());
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round().unwrap() {
                Protocol::NotDone(_) => panic!("party {} not done, expect done", i),
                Protocol::Done(Ok(secret_key_share)) => secret_key_share,
                Protocol::Done(Err(criminals)) => panic!(
                    "party {} expect success got failure with criminals: {:?}",
                    i, criminals
                ),
            }
        })
        .collect();

    // test: consensus on pubkeys
    let mut pubkeys_iter = all_secret_key_shares.iter().map(|(_, s)| s.group());
    let first_verifying_keys = pubkeys_iter.next().unwrap();
    for verifying_keys in pubkeys_iter {
        assert_eq!(verifying_keys, first_verifying_keys);
    }

    // test: each party's signing key matches her verifying key
    for (share_id, secret_key_share) in all_secret_key_shares.iter() {
        let verifying_key =
            k256::ProjectivePoint::generator() * secret_key_share.share().signing_key().as_ref();
        assert_eq!(
            &verifying_key,
            secret_key_share
                .group()
                .all_pubkeys()
                .get(share_id)
                .unwrap()
                .as_ref()
        );
    }

    // TODO Test secret key share recovery on every keygen
    // share_recovery(
    //     party_share_counts,
    //     threshold,
    //     secret_recovery_keys,
    //     session_nonce,
    //     &all_secret_key_shares,
    // );

    all_secret_key_shares
}
