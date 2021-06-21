use super::*;
use crate::{fillvec::FillVec, protocol2::RoundOutput::*};
use rand::RngCore;
use tracing_test::traced_test;

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

    let r0_parties: Vec<RoundWaiter<KeygenOutput>> = (0..share_count)
        .map(|i| {
            new_keygen(
                share_count,
                threshold,
                i,
                &secret_recovery_keys[i],
                session_nonce,
            )
            .unwrap()
        })
        .collect();

    // execute round 1 all parties
    let mut r1_parties: Vec<RoundWaiter<KeygenOutput>> = r0_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.msgs_out().bcast.is_none());
            assert!(party.msgs_out().p2ps.is_none());
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round() {
                NotDone(next_round) => next_round,
                Done(_) => panic!("party {} done, expect not done", i),
            }
        })
        .collect();

    // deliver r1 messages
    let r1_bcasts: Vec<Vec<u8>> = r1_parties
        .iter()
        .map(|party| party.msgs_out().bcast.as_ref().unwrap().clone())
        .collect();
    for party in r1_parties.iter_mut() {
        for (from, msg) in r1_bcasts.iter().enumerate() {
            party.bcast_in(from, msg);
        }
    }

    // save each u for later tests
    let all_u_secrets: Vec<k256::Scalar> = r1_parties
        .iter()
        .map(|party| {
            party
                .round
                .as_any()
                .downcast_ref::<r2::R2>()
                .unwrap()
                .r1state
                .u_i_vss
                .get_secret()
                .clone()
        })
        .collect();

    // execute round 2 all parties
    let mut r2_parties: Vec<RoundWaiter<KeygenOutput>> = r1_parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            assert!(party.msgs_out().bcast.is_some());
            assert!(party.msgs_out().p2ps.is_none());
            assert!(!party.expecting_more_msgs_this_round());
            match party.execute_next_round() {
                NotDone(next_round) => next_round,
                Done(_) => panic!("party {} done, expect not done", i),
            }
        })
        .collect();

    // deliver r2 messages
    let r2_bcasts: Vec<Vec<u8>> = r2_parties
        .iter()
        .map(|party| party.msgs_out().bcast.as_ref().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, msg) in r2_bcasts.iter().enumerate() {
            party.bcast_in(from, msg);
        }
    }
    let r2_p2ps: Vec<FillVec<Vec<u8>>> = r2_parties
        .iter()
        .map(|party| party.msgs_out().p2ps.as_ref().unwrap().clone())
        .collect();
    for party in r2_parties.iter_mut() {
        for (from, p2ps) in r2_p2ps.iter().enumerate() {
            for (to, msg) in p2ps.vec_ref().iter().enumerate() {
                if let Some(msg) = msg {
                    party.p2p_in(from, to, msg);
                }
            }
        }
    }

    // TEMPORARY test until r3 is done
    for party in r2_parties.iter() {
        assert!(party.msgs_out().bcast.is_some());
        assert!(party.msgs_out().p2ps.is_some());
        assert!(!party.expecting_more_msgs_this_round());
    }

    // execute round 3 all parties and store their outputs
    // let mut r3_parties: Vec<RoundWaiter<KeygenOutput>> = r2_parties
    //     .into_iter()
    //     .enumerate()
    //     .map(|(i, party)| {
    //         assert!(party.bcast_out().is_some());
    //         assert!(party.p2ps_out().is_some());
    //         assert!(party.bcasts_in.is_full());
    //         // assert!(party.p2ps_in.is_empty());
    //         assert!(!party.expecting_more_msgs_this_round());
    //         match party.execute_next_round() {
    //             NotDone(next_round) => next_round,
    //             Done(_) => panic!("party {} done, expect not done", i),
    //         }
    //     })
    //     .collect();

    // DONE TO HERE

    // // deliver round 3 msgs
    // for party in r0_parties.iter_mut() {
    //     party.in_r3bcasts = all_r3_bcasts.clone();
    // }

    // // execute round 4 all parties and store their outputs
    // let mut all_secret_key_shares = Vec::with_capacity(share_count);
    // for party in r0_parties.iter_mut() {
    //     match party.r4() {
    //         r4::Output::Success { key_share } => {
    //             all_secret_key_shares.push(key_share);
    //         }
    //         r4::Output::Fail { criminals } => {
    //             panic!(
    //                 "r4 party {} expect success got failure with criminals: {:?}",
    //                 party.my_index, criminals
    //             );
    //         }
    //     }
    //     party.status = Status::Done;
    // }
    // let all_secret_key_shares = all_secret_key_shares; // make read-only

    // // test: reconstruct the secret key in two ways:
    // // 1. from all the u secrets of round 1
    // // 2. from the first t+1 shares
    // let secret_key_sum_u = all_u_secrets
    //     .iter()
    //     .fold(k256::Scalar::zero(), |acc, &x| acc + x);

    // let all_shares: Vec<vss_k256::Share> = all_secret_key_shares
    //     .iter()
    //     .map(|k| vss_k256::Share::from_scalar(*k.share.x_i.unwrap(), k.share.index))
    //     .collect();
    // let secret_key_recovered = vss_k256::recover_secret(&all_shares, threshold);

    // assert_eq!(secret_key_recovered, secret_key_sum_u);

    // // test: verify that the reconstructed secret key yields the public key everyone deduced
    // for secret_key_share in all_secret_key_shares.iter() {
    //     let test_pubkey = k256::ProjectivePoint::generator() * secret_key_recovered;
    //     assert_eq!(&test_pubkey, secret_key_share.group.y.unwrap());
    // }

    // // test: everyone computed everyone else's public key share correctly
    // for (i, secret_key_share) in all_secret_key_shares.iter().enumerate() {
    //     for (j, other_secret_key_share) in all_secret_key_shares.iter().enumerate() {
    //         assert_eq!(
    //             *secret_key_share.group.all_shares[j].X_i.unwrap(),
    //             k256::ProjectivePoint::generator() * other_secret_key_share.share.x_i.unwrap(),
    //             "party {} got party {} key wrong",
    //             i,
    //             j
    //         );
    //     }
    // }

    // all_secret_key_shares
    Vec::new()
}

/// for brevity only
fn t(n: usize, t: usize) -> TestCase {
    TestCase {
        share_count: n,
        threshold: t,
    }
}
