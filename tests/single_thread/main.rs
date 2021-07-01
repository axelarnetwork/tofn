use rand::RngCore;
use tofn::{
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{new_keygen, KeygenOutput, KeygenPartyIndex},
        protocol::{Protocol, ProtocolRound},
        BytesVec, TofnResult,
    },
    vecmap::{HoleVecMap, VecMap},
};
use tracing::error;
use tracing_test::traced_test; // enable logs in tests

/// TODO rename parent dir to `example`
/// TODO clean up
// TODO generic over final output F

#[test]
#[traced_test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    let mut parties: Vec<Protocol<KeygenOutput, KeygenPartyIndex>> = (0..share_count)
        .map(|index| {
            let mut secret_recovery_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut secret_recovery_key);
            new_keygen(
                share_count,
                threshold,
                index,
                &secret_recovery_key,
                session_nonce,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    while nobody_done(&parties) {
        parties = next_round(parties);
    }

    let results: Vec<SecretKeyShare> = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| match party {
            Protocol::NotDone(_) => panic!("party {} not done yet", i),
            Protocol::Done(result) => result.expect("party finished with error"),
        })
        .collect();

    println!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        println!("party {} secret info: {:?}", i, result.share);
    }
}

// TODO generic over final output F
fn nobody_done(parties: &[Protocol<KeygenOutput, KeygenPartyIndex>]) -> bool {
    parties
        .iter()
        .all(|party| matches!(party, Protocol::NotDone(_)))
}

// TODO generic over final output F
fn next_round(
    parties: Vec<Protocol<KeygenOutput, KeygenPartyIndex>>,
) -> Vec<Protocol<KeygenOutput, KeygenPartyIndex>> {
    // extract current round from parties
    let mut rounds: Vec<ProtocolRound<KeygenOutput, KeygenPartyIndex>> = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| match party {
            Protocol::NotDone(round) => round,
            Protocol::Done(_) => panic!("party {} done too early", i),
        })
        .collect();

    // deliver bcasts
    let bcasts: VecMap<KeygenPartyIndex, Option<TofnResult<BytesVec>>> = rounds
        .iter()
        .map(|round| round.bcast_out().clone())
        .collect();
    for (from, bcast) in bcasts.into_iter() {
        if let Some(bcast) = bcast {
            match bcast {
                Ok(bytes) => {
                    for round in rounds.iter_mut() {
                        round.bcast_in(from, &bytes);
                    }
                }
                Err(e) => error!("bcast error from party {}: {}", from, e),
            };
        }
    }

    // deliver p2ps
    let all_p2ps: VecMap<
        KeygenPartyIndex,
        Option<TofnResult<HoleVecMap<KeygenPartyIndex, BytesVec>>>,
    > = rounds
        .iter()
        .map(|round| round.p2ps_out().clone())
        .collect();
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            match p2ps {
                Ok(p2ps) => {
                    for (to, bytes) in p2ps {
                        for round in rounds.iter_mut() {
                            round.p2p_in(from.as_usize(), to.as_usize(), &bytes);
                        }
                    }
                }
                Err(e) => error!("p2p error from party {}: {}", from, e),
            };
        }
    }

    // compute next round's parties
    rounds
        .into_iter()
        .enumerate()
        .map(|(i, round)| {
            assert!(
                !round.expecting_more_msgs_this_round(),
                "party {} should not be expecting more messages this round",
                i
            );
            round.execute_next_round()
        })
        .collect()
}
