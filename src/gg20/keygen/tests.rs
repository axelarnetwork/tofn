use super::*;
use crate::{
    collections::{zip2, HoleVecMap, TypedUsize, VecMap},
    crypto_tools::{rng, vss},
    sdk::api::{BytesVec, Protocol},
};
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use crate::gg20::keygen::malicious::Behaviour::Honest;

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
    pub secret_recovery_keys: VecMap<KeygenPartyId, rng::SecretRecoveryKey>,
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
    secret_recovery_keys: &VecMap<KeygenPartyId, rng::SecretRecoveryKey>,
    session_nonce: &[u8],
) -> VecMap<KeygenShareId, SecretKeyShare> {
    assert_eq!(secret_recovery_keys.len(), party_share_counts.party_count());
    let share_count = party_share_counts.total_share_count();

    let mut r1_parties: Vec<_> = party_share_counts
        .iter()
        .map(|(party_id, &party_share_count)| {
            let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                party_id,
                secret_recovery_keys.get(party_id).unwrap(),
                session_nonce,
            )
            .unwrap();

            (0..party_share_count).map(move |subshare_id| {
                // each party use the same secret recovery key for all its subshares
                match new_keygen(
                    party_share_counts.clone(),
                    threshold,
                    party_id,
                    subshare_id,
                    &party_keygen_data,
                    #[cfg(feature = "malicious")]
                    Honest,
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

    // save each u for later tests
    let all_u_secrets: Vec<k256::Scalar> = r1_parties
        .iter()
        .map(|party| {
            *party
                .round_as_any()
                .downcast_ref::<r2::R2>()
                .unwrap()
                .u_i_vss
                .get_secret()
        })
        .collect();

    // execute round 2 all parties
    let mut r2_parties: Vec<_> = r1_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.bcast_out().is_some());
            assert!(party.p2ps_out().is_none());
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round().unwrap() {
                Protocol::NotDone(next_round) => next_round,
                Protocol::Done(_) => panic!("party {} done, expect not done", i),
            }
        })
        .collect();

    // deliver r2 messages
    let r2_bcasts: VecMap<KeygenShareId, BytesVec> = r2_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, bytes) in r2_bcasts.iter() {
            party
                .msg_in(party_share_counts.share_to_party_id(from).unwrap(), bytes)
                .unwrap();
        }
    }
    let r2_p2ps: VecMap<KeygenShareId, HoleVecMap<KeygenShareId, BytesVec>> = r2_parties
        .iter()
        .map(|party| party.p2ps_out().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, p2ps) in r2_p2ps.iter() {
            for (_, bytes) in p2ps.iter() {
                party
                    .msg_in(party_share_counts.share_to_party_id(from).unwrap(), bytes)
                    .unwrap();
            }
        }
    }

    // execute round 3 all parties
    let mut r3_parties: Vec<_> = r2_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.bcast_out().is_some());
            assert!(party.p2ps_out().as_ref().unwrap().len() == share_count);
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round().unwrap() {
                Protocol::NotDone(next_round) => next_round,
                Protocol::Done(_) => panic!("party {} done, expect not done", i),
            }
        })
        .collect();

    // deliver r3 messages
    let r3_bcasts: VecMap<KeygenShareId, BytesVec> = r3_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r3_parties.iter_mut() {
        for (from, bytes) in r3_bcasts.iter() {
            party
                .msg_in(party_share_counts.share_to_party_id(from).unwrap(), bytes)
                .unwrap();
        }
    }

    // execute round 3 all parties
    let all_secret_key_shares: VecMap<KeygenShareId, SecretKeyShare> = r3_parties
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

    // test: reconstruct the secret key in two ways:
    // 1. from all the u secrets of round 1
    // 2. from the first t+1 shares
    let secret_key_sum_u = all_u_secrets
        .iter()
        .fold(k256::Scalar::zero(), |acc, &x| acc + x);

    let all_vss_shares: Vec<vss::Share> = all_secret_key_shares
        .iter()
        .map(|(id, k)| vss::Share::from_scalar(*k.share().x_i().as_ref(), id.as_usize()))
        .collect();
    let secret_key_recovered = vss::recover_secret(&all_vss_shares);

    assert_eq!(secret_key_recovered, secret_key_sum_u);

    // test: verify that the reconstructed secret key yields the public key everyone deduced
    for (share_id, secret_key_share) in all_secret_key_shares.iter() {
        let test_pubkey = k256::ProjectivePoint::generator() * secret_key_recovered;
        assert_eq!(
            &test_pubkey,
            secret_key_share.group().y().as_ref(),
            "share {} has invalid pub key",
            share_id
        );
    }

    // test: everyone computed everyone else's public key share correctly
    for (i, secret_key_share) in all_secret_key_shares.iter() {
        for (j, other_secret_key_share) in all_secret_key_shares.iter() {
            assert_eq!(
                *secret_key_share
                    .group()
                    .all_shares()
                    .get(j)
                    .unwrap()
                    .X_i()
                    .as_ref(),
                k256::ProjectivePoint::generator() * other_secret_key_share.share().x_i().as_ref(),
                "party {} got party {} key wrong",
                i,
                j
            );
        }
    }

    // Test secret key share recovery on every keygen
    share_recovery(
        party_share_counts,
        threshold,
        secret_recovery_keys,
        session_nonce,
        &all_secret_key_shares,
    );

    all_secret_key_shares
}

fn share_recovery(
    party_share_counts: &KeygenPartyShareCounts,
    threshold: usize,
    secret_recovery_keys: &VecMap<KeygenPartyId, rng::SecretRecoveryKey>,
    session_nonce: &[u8],
    shares: &VecMap<KeygenShareId, SecretKeyShare>,
) {
    let recovery_info_bytes: VecMap<KeygenShareId, _> = shares
        .iter()
        .map(|(_, s)| s.recovery_info().unwrap())
        .collect();

    // The public info of any party should work for all shares
    let first_share_id = TypedUsize::from_usize(0);
    let group_info = shares.get(first_share_id).unwrap().group();
    let group_info_bytes = group_info.all_shares_bytes().unwrap();
    let pubkey_bytes = group_info.encoded_pubkey();

    let recovered_party_keypairs: VecMap<KeygenPartyId, PartyKeyPair> = (0..party_share_counts
        .party_count())
        .map(|party_id| {
            let party_id = TypedUsize::from_usize(party_id);

            recover_party_keypair_unsafe(
                party_id,
                secret_recovery_keys.get(party_id).unwrap(),
                session_nonce,
            )
            .unwrap()
        })
        .collect();

    let recovered_shares = recovery_info_bytes.map2(|(share_id, recovery_info)| {
        let (party_id, subshare_id) = party_share_counts
            .share_to_party_subshare_ids(share_id)
            .unwrap();
        let party_keypair = recovered_party_keypairs.get(party_id).unwrap();

        SecretKeyShare::recover(
            party_keypair,
            &recovery_info,
            &group_info_bytes,
            &pubkey_bytes,
            party_id,
            subshare_id,
            party_share_counts.clone(),
            threshold,
        )
        .unwrap()
    });

    for ((i, s), (_, r)) in shares.iter().zip(recovered_shares.iter()) {
        assert_eq!(s.share(), r.share(), "party {}", i);
        for (j, ss, rr) in zip2(s.group().all_shares(), r.group().all_shares()) {
            assert_eq!(ss.X_i(), rr.X_i(), "party {} public info on party {}", i, j);
            assert_eq!(ss.ek(), rr.ek(), "party {} public info on party {}", i, j);
            assert_eq!(ss.zkp(), rr.zkp(), "party {} public info on party {}", i, j);
        }
        assert_eq!(s.group().threshold(), r.group().threshold(), "party {}", i);
        assert_eq!(s.group().y(), r.group().y(), "party {}", i);
    }

    // Also test that equality works on the share struct
    assert_eq!(&recovered_shares, shares);
}

/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key(index: usize) -> rng::SecretRecoveryKey {
    let index_bytes = index.to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    rng::SecretRecoveryKey(result)
}
