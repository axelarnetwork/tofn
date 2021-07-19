//! Single-threaded generic protocol execution

use tofn::{
    refactor::collections::{HoleVecMap, VecMap},
    refactor::sdk::api::{BytesVec, Protocol, TofnResult},
};
use tracing::warn;

pub fn execute_protocol<F, K, P>(
    mut parties: VecMap<K, Protocol<F, K, P>>,
) -> TofnResult<VecMap<K, Protocol<F, K, P>>>
where
    K: Clone,
{
    while nobody_done(&parties) {
        parties = next_round(parties)?;
    }
    Ok(parties)
}

pub fn nobody_done<F, K, P>(parties: &VecMap<K, Protocol<F, K, P>>) -> bool {
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

fn next_round<F, K, P>(
    parties: VecMap<K, Protocol<F, K, P>>,
) -> TofnResult<VecMap<K, Protocol<F, K, P>>>
where
    K: Clone,
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
        .map(|(_, round)| round.bcast_out().cloned())
        .collect();
    for (from, bcast) in bcasts.into_iter() {
        if let Some(bytes) = bcast {
            for (_, round) in rounds.iter_mut() {
                round.msg_in(
                    round
                        .info()
                        .party_share_counts()
                        .share_to_party_id(from)
                        .unwrap(),
                    &bytes,
                )?;
            }
        }
    }

    // deliver p2ps
    let all_p2ps: VecMap<K, Option<HoleVecMap<K, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().cloned())
        .collect();
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            for (_, bytes) in p2ps {
                for (_, round) in rounds.iter_mut() {
                    round.msg_in(
                        round
                            .info()
                            .party_share_counts()
                            .share_to_party_id(from)
                            .unwrap(), // no easy access to from_party_id
                        &bytes,
                    )?;
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
        .collect::<TofnResult<_>>()
}
