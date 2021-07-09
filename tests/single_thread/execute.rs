//! Single-threaded generic protocol execution

use tofn::{
    refactor::api::{BytesVec, Protocol},
    vecmap::{Behave, HoleVecMap, VecMap},
};
use tracing::warn;

pub fn execute_protocol<F, K>(mut parties: VecMap<K, Protocol<F, K>>) -> VecMap<K, Protocol<F, K>>
where
    K: Behave,
{
    while nobody_done(&parties) {
        parties = next_round(parties);
    }
    parties
}

fn nobody_done<F, K>(parties: &VecMap<K, Protocol<F, K>>) -> bool
where
    K: Behave,
{
    // warn if there's disagreement
    let (mut done, mut not_done) = (
        Vec::with_capacity(parties.len()),
        Vec::with_capacity(parties.len()),
    );
    for (i, party) in parties.iter() {
        if matches!(party, Protocol::Done(_)) {
            done.push(i);
        } else {
            not_done.push(i);
        }
    }
    if !done.is_empty() && !not_done.is_empty() {
        warn!(
            "disagreement: done parties {:?}, not done parties {:?}",
            done, not_done
        );
    }
    done.is_empty()
}

fn next_round<F, K>(parties: VecMap<K, Protocol<F, K>>) -> VecMap<K, Protocol<F, K>>
where
    K: Behave,
{
    // extract current round from parties
    let mut rounds: VecMap<K, _> = parties
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(round) => round,
            Protocol::Done(_) => panic!("next_round called but party {} is done", i),
        })
        .collect();

    // deliver bcasts
    let bcasts: VecMap<K, Option<BytesVec>> = rounds
        .iter()
        .map(|(_, round)| round.bcast_out().clone())
        .collect();
    for (from, bcast) in bcasts.into_iter() {
        if let Some(bytes) = bcast {
            for (_, round) in rounds.iter_mut() {
                round.bcast_in(from, &bytes);
            }
        }
    }

    // deliver p2ps
    let all_p2ps: VecMap<K, Option<HoleVecMap<K, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().clone())
        .collect();
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            for (to, bytes) in p2ps {
                for (_, round) in rounds.iter_mut() {
                    round.p2p_in(from, to, &bytes);
                }
            }
        }
    }

    // compute next round's parties
    rounds
        .into_iter()
        .map(|(i, round)| {
            if round.expecting_more_msgs_this_round() {
                warn!(
                    "all messages delivered this round but party {} still expecting messages",
                    i,
                );
            }
            round.execute_next_round()
        })
        .collect()
}
