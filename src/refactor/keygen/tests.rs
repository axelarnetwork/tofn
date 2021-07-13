use super::*;
use crate::{
    protocol::gg20::vss_k256,
    refactor::collections::{HoleVecMap, TypedUsize, VecMap},
    refactor::protocol::api::{BytesVec, Protocol},
};
use rand::RngCore;
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use crate::refactor::keygen::malicious::Behaviour::Honest;
pub struct TestCase {
    share_count: usize,
    threshold: usize,
}

lazy_static::lazy_static! {
    pub static ref TEST_CASES: Vec<TestCase>
    // = vec![t(5, 0), t(5, 1), t(5, 3), t(5, 4)];
    = vec![t(5, 3)];
}

#[test]
#[traced_test]
fn basic_correctness() {
    for t in TEST_CASES.iter() {
        execute_keygen(t.share_count, t.threshold);
    }
}

pub(crate) fn execute_keygen(share_count: usize, threshold: usize) -> Vec<SecretKeyShare> {
    execute_keygen_with_recovery(share_count, threshold).shares
}

pub(crate) struct KeySharesWithRecovery {
    pub shares: Vec<SecretKeyShare>,
    pub secret_recovery_keys: Vec<SecretRecoveryKey>,
    pub session_nonce: Vec<u8>,
}

pub(crate) fn execute_keygen_with_recovery(
    share_count: usize,
    threshold: usize,
) -> KeySharesWithRecovery {
    let mut secret_recovery_keys = vec![[0u8; 64]; share_count];
    for s in secret_recovery_keys.iter_mut() {
        rand::thread_rng().fill_bytes(s);
    }
    let session_nonce = b"foobar".to_vec();

    KeySharesWithRecovery {
        shares: execute_keygen_from_recovery(threshold, &secret_recovery_keys, &session_nonce),
        secret_recovery_keys,
        session_nonce,
    }
}

pub(crate) fn execute_keygen_from_recovery(
    threshold: usize,
    secret_recovery_keys: &[SecretRecoveryKey],
    session_nonce: &[u8],
) -> Vec<SecretKeyShare> {
    let share_count = secret_recovery_keys.len();

    let r0_parties: Vec<_> = (0..share_count)
        .map(|i| {
            match new_keygen(
                share_count,
                threshold,
                TypedUsize::from_usize(i),
                &secret_recovery_keys[i],
                session_nonce,
                #[cfg(feature = "malicious")]
                Honest,
            )
            .unwrap()
            {
                Protocol::NotDone(round) => round,
                Protocol::Done(_) => panic!("`new_keygen` returned a `Done` protocol"),
            }
        })
        .collect();

    // execute round 1 all parties
    let mut r1_parties: Vec<_> = r0_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.bcast_out().is_none());
            assert!(party.p2ps_out().is_none());
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round().unwrap() {
                Protocol::NotDone(next_round) => next_round,
                Protocol::Done(_) => panic!("party {} done, expect not done", i),
            }
        })
        .collect();

    // deliver r1 messages
    let r1_bcasts: VecMap<KeygenPartyIndex, BytesVec> = r1_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r1_parties.iter_mut() {
        for (from, bytes) in r1_bcasts.iter() {
            party.bcast_in(from, bytes).unwrap();
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
    let r2_bcasts: VecMap<KeygenPartyIndex, BytesVec> = r2_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, bytes) in r2_bcasts.iter() {
            party.bcast_in(from, bytes).unwrap();
        }
    }
    let r2_p2ps: VecMap<KeygenPartyIndex, HoleVecMap<KeygenPartyIndex, BytesVec>> = r2_parties
        .iter()
        .map(|party| party.p2ps_out().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, p2ps) in r2_p2ps.iter() {
            for (to, msg) in p2ps.iter() {
                party.p2p_in(from, to, msg).unwrap();
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
    let r3_bcasts: VecMap<KeygenPartyIndex, BytesVec> = r3_parties
        .iter()
        .map(|party| party.bcast_out().unwrap().clone())
        .collect();
    for party in r3_parties.iter_mut() {
        for (from, bytes) in r3_bcasts.iter() {
            party.bcast_in(from, bytes).unwrap();
        }
    }

    // execute round 3 all parties
    let all_secret_key_shares: Vec<SecretKeyShare> = r3_parties
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

    let all_shares: Vec<vss_k256::Share> = all_secret_key_shares
        .iter()
        .map(|k| vss_k256::Share::from_scalar(*k.share.x_i.unwrap(), k.share.index.as_usize()))
        .collect();
    let secret_key_recovered = vss_k256::recover_secret(&all_shares, threshold);

    assert_eq!(secret_key_recovered, secret_key_sum_u);

    // test: verify that the reconstructed secret key yields the public key everyone deduced
    for secret_key_share in all_secret_key_shares.iter() {
        let test_pubkey = k256::ProjectivePoint::generator() * secret_key_recovered;
        assert_eq!(&test_pubkey, secret_key_share.group.y.unwrap());
    }

    // test: everyone computed everyone else's public key share correctly
    // TODO why not use VecMap?
    for (i, secret_key_share) in all_secret_key_shares.iter().enumerate() {
        for (j, other_secret_key_share) in all_secret_key_shares.iter().enumerate() {
            assert_eq!(
                *secret_key_share
                    .group
                    .all_shares
                    .get(TypedUsize::from_usize(j))
                    .unwrap()
                    .X_i
                    .unwrap(),
                k256::ProjectivePoint::generator() * other_secret_key_share.share.x_i.unwrap(),
                "party {} got party {} key wrong",
                i,
                j
            );
        }
    }

    all_secret_key_shares
}

/// for brevity only
fn t(n: usize, t: usize) -> TestCase {
    TestCase {
        share_count: n,
        threshold: t,
    }
}
