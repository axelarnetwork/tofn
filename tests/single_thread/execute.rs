//! Single-threaded generic protocol execution

use tofn::{
    refactor::{
        protocol::{Protocol, ProtocolRound},
        BytesVec, TofnResult,
    },
    vecmap::{HoleVecMap, VecMap},
};
use tracing::error;

pub fn execute_protocol<F, K>(mut parties: Vec<Protocol<F, K>>) -> Vec<Protocol<F, K>>
where
    K: Clone,
{
    while nobody_done(&parties) {
        parties = next_round(parties);
    }
    parties
}

fn nobody_done<F, K>(parties: &[Protocol<F, K>]) -> bool
where
    K: Clone,
{
    parties
        .iter()
        .all(|party| matches!(party, Protocol::NotDone(_)))
}

fn next_round<F, K>(parties: Vec<Protocol<F, K>>) -> Vec<Protocol<F, K>>
where
    K: Clone,
{
    // extract current round from parties
    let mut rounds: Vec<ProtocolRound<F, K>> = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| match party {
            Protocol::NotDone(round) => round,
            Protocol::Done(_) => panic!("party {} done too early", i),
        })
        .collect();

    // deliver bcasts
    let bcasts: VecMap<K, Option<TofnResult<BytesVec>>> = rounds
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
    let all_p2ps: VecMap<K, Option<TofnResult<HoleVecMap<K, BytesVec>>>> = rounds
        .iter()
        .map(|round| round.p2ps_out().clone())
        .collect();
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            match p2ps {
                Ok(p2ps) => {
                    for (to, bytes) in p2ps {
                        for round in rounds.iter_mut() {
                            round.p2p_in(from, to, &bytes);
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
