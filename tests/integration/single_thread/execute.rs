//! Single-threaded generic protocol execution

use tofn::{
    collections::{HoleVecMap, TypedUsize, VecMap},
    sdk::api::{BytesVec, Protocol, TofnResult},
};
use tracing::{debug, warn};

pub fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    mut parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
where
    K: Clone,
{
    let mut current_round = 0;
    while nobody_done(&parties) {
        current_round += 1;
        parties = next_round(parties, current_round)?;
    }
    Ok(parties)
}

pub fn nobody_done<F, K, P, const MAX_MSG_IN_LEN: usize>(
    parties: &VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
) -> bool {
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

fn next_round<F, K, P, const MAX_MSG_IN_LEN: usize>(
    parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
    current_round: usize,
) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
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
            if from.as_usize() == 0 {
                debug!("round {} bcast byte length {}", current_round, bytes.len());
            }

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
            if from.as_usize() == 0 {
                debug!(
                    "round {} p2p byte length {}",
                    current_round,
                    p2ps.get(TypedUsize::from_usize(1)).unwrap().len()
                );
            }
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
