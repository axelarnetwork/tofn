//! Single-threaded generic protocol execution
//! with a missing or corrupted message

use tofn::{
    refactor::collections::{Behave, HoleVecMap, VecMap},
    refactor::{
        collections::TypedUsize,
        protocol::api::{BytesVec, Protocol, TofnResult},
    },
};
use tracing::{info, warn};

pub struct TestFault<K>
where
    K: Behave,
{
    pub party: TypedUsize<K>, // faulter party
    pub round: usize,         // round in which fault occurs, starting at 1
    pub msg: RoundMessage<K>, // which message is corrupted
    pub fault_type: FaultType,
}

pub enum RoundMessage<K>
where
    K: Behave,
{
    Bcast,
    P2p { victim: TypedUsize<K> },
}

pub enum FaultType {
    Timeout,
    Corruption,
}

pub fn execute_protocol<F, K>(
    mut parties: VecMap<K, Protocol<F, K>>,
    fault: &TestFault<K>,
) -> TofnResult<VecMap<K, Protocol<F, K>>>
where
    K: Behave,
{
    let mut current_round = 0;
    while nobody_done(&parties) {
        parties = next_round(parties, fault, current_round)?;
        current_round += 1;
    }
    Ok(parties)
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

fn next_round<F, K>(
    parties: VecMap<K, Protocol<F, K>>,
    fault: &TestFault<K>,
    current_round: usize,
) -> TofnResult<VecMap<K, Protocol<F, K>>>
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

    // collect bcasts
    let mut bcasts: VecMap<K, Option<BytesVec>> = rounds
        .iter()
        .map(|(_, round)| round.bcast_out().cloned())
        .collect();

    // inject fault
    if current_round == fault.round && matches!(fault.msg, RoundMessage::Bcast) {
        let bcast = bcasts.get_mut(fault.party)?;
        assert!(
            bcast.is_some(),
            "round {} has no bcasts to fault",
            fault.round
        );
        *bcast = match fault.fault_type {
            FaultType::Timeout => {
                info!(
                    "drop bcast from party {} in round {}",
                    fault.party, fault.round
                );
                None
            }
            FaultType::Corruption => {
                info!(
                    "corrupt bcast from party {} in round {}",
                    fault.party, fault.round
                );
                Some(b"these bytes are corrupted 1234".to_vec())
            }
        }
    }

    // deliver bcasts
    for (from, bcast) in bcasts.into_iter() {
        if let Some(bytes) = bcast {
            for (_, round) in rounds.iter_mut() {
                round.bcast_in(from, &bytes)?;
            }
        }
    }

    // collect p2ps
    let all_p2ps: VecMap<K, Option<HoleVecMap<K, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().cloned())
        .collect();
    if current_round == fault.round && matches!(fault.msg, RoundMessage::P2p { victim: _ }) {
        assert!(
            all_p2ps.iter().all(|(_, p2ps)| p2ps.is_some()),
            "round {} has no p2ps to fault",
            fault.round
        );
    }

    // deliver p2ps
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            for (to, mut bytes) in p2ps {
                // inject fault
                if current_round == fault.round {
                    if let RoundMessage::P2p { victim } = fault.msg {
                        if victim == to && fault.party == from {
                            match fault.fault_type {
                                FaultType::Timeout => {
                                    info!(
                                        "drop p2p from party {} to {} in round {}",
                                        fault.party, victim, fault.round
                                    );
                                    continue;
                                }
                                FaultType::Corruption => {
                                    info!(
                                        "corrupt p2p from party {} to {} in round {}",
                                        fault.party, victim, fault.round
                                    );
                                    bytes = b"these bytes are corrupted 1234".to_vec()
                                }
                            }
                        }
                    }
                }

                // deliver p2p to all parties
                for (_, round) in rounds.iter_mut() {
                    round.p2p_in(from, to, &bytes)?;
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
                    "all messages delivered in round {} but party {} still expecting messages",
                    current_round, i,
                );
            }
            round.execute_next_round()
        })
        .collect::<TofnResult<_>>()
}
