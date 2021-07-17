//! Single-threaded generic protocol execution
//! with a missing or corrupted message

use self::{FaultType::*, MsgType::*};
use tofn::refactor::{
    collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
    protocol::api::{BytesVec, Fault, MsgType, Protocol, TofnResult},
};
use tracing::{info, warn};
use tracing_test::traced_test; // enable logs in tests

use crate::{execute::nobody_done, keygen::initialize_honest_parties};

#[test]
#[traced_test]
fn single_faults_keygen() {
    let (share_count, threshold) = (5, 2);
    info!(
        "all tests: share_count [{}] threshold [{}]",
        share_count, threshold
    );

    for test_case in single_fault_test_case_list() {
        let parties = initialize_honest_parties(share_count, threshold);
        info!(
            "test: msg [{:?}], type [{:?}]",
            test_case.msg, test_case.fault_type
        );
        execute_test_case(parties, test_case);
    }
}

pub fn single_fault_test_case_list<K, P>() -> Vec<SingleFaulterTestCase<K, P>> {
    let zero = TypedUsize::from_usize(0);
    vec![
        single_fault_test_case(Bcast, Timeout),
        single_fault_test_case(P2p { to: zero }, Timeout),
        single_fault_test_case(Bcast, Corruption),
        single_fault_test_case(P2p { to: zero }, Corruption),
    ]
}

fn single_fault_test_case<K, P>(
    msg: MsgType<K>,
    fault_type: FaultType,
) -> SingleFaulterTestCase<K, P> {
    // 5 parties, faulter: 3, round: 2
    let faulter_share_id = TypedUsize::from_usize(3);
    let faulter_party_id = TypedUsize::from_usize(3);
    let mut faulters = FillVecMap::with_size(5);
    let fault = match fault_type {
        FaultType::Timeout => Fault::MissingMessage,
        FaultType::Corruption => Fault::CorruptedMessage,
    };
    faulters.set(faulter_party_id, fault).unwrap();
    SingleFaulterTestCase {
        faulter_share_id,
        faulter_party_id,
        round: 2,
        msg,
        fault_type,
        expected_honest_output: faulters,
    }
}

pub struct SingleFaulterTestCase<K, P> {
    pub faulter_share_id: TypedUsize<K>,
    pub faulter_party_id: TypedUsize<P>,
    pub round: usize,          // round in which fault occurs, index starts at 1
    pub msg: MsgType<K>,       // which message is faulty
    pub fault_type: FaultType, // missing or corrupted message
    pub expected_honest_output: FillVecMap<P, Fault>,
}

#[derive(Debug)]

pub enum FaultType {
    Timeout,
    Corruption,
}

fn execute_test_case<F, K, P>(
    parties: VecMap<K, Protocol<F, K, P>>,
    test_case: SingleFaulterTestCase<K, P>,
) where
    K: PartialEq + std::fmt::Debug + Clone + Copy, // TODO can't quite escape ugly trait bounds :(
    P: PartialEq + std::fmt::Debug + Clone + Copy,
{
    let parties = execute_protocol(parties, &test_case).expect("internal tofn error");

    // TEST: honest parties finished and produced the expected output
    for (i, party) in parties.iter() {
        if i != test_case.faulter_share_id {
            let result = match party {
                Protocol::NotDone(_) => panic!("honest party {} not done yet", i),
                Protocol::Done(result) => result,
            };
            match result {
                Ok(_) => panic!("expect failure, got success"),
                Err(got_faulters) => {
                    assert_eq!(*got_faulters, test_case.expected_honest_output);
                }
            }
        }
    }
}

pub fn execute_protocol<F, K, P>(
    mut parties: VecMap<K, Protocol<F, K, P>>,
    test_case: &SingleFaulterTestCase<K, P>,
) -> TofnResult<VecMap<K, Protocol<F, K, P>>>
where
    K: Clone + Copy,
{
    let mut current_round = 0;
    while nobody_done(&parties) {
        parties = next_round(parties, test_case, current_round)?;
        current_round += 1;
    }
    Ok(parties)
}

fn next_round<F, K, P>(
    parties: VecMap<K, Protocol<F, K, P>>,
    test_case: &SingleFaulterTestCase<K, P>,
    current_round: usize,
) -> TofnResult<VecMap<K, Protocol<F, K, P>>>
where
    K: Clone + Copy,
{
    // extract current round from parties
    let mut rounds: VecMap<K, _> = parties
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(round) => round,
            Protocol::Done(_) => panic!("next_round called but party {} is done", i),
        })
        .collect();

    // inject corruption fault
    if current_round == test_case.round && matches!(test_case.fault_type, Corruption) {
        info!(
            "corrupt msg from {} in round {}",
            test_case.faulter_share_id, test_case.round
        );
        rounds
            .get_mut(test_case.faulter_share_id)?
            .corrupt_msg_payload(test_case.msg)?;
    }

    // collect bcasts
    let bcasts: Option<VecMap<K, BytesVec>> = rounds
        .iter()
        .map(|(_, round)| round.bcast_out().cloned())
        .collect();

    // deliver bcasts if present
    if let Some(bcasts) = bcasts {
        for (from, bytes) in bcasts.into_iter() {
            // inject timeout fault
            if current_round == test_case.round
                && test_case.faulter_share_id == from
                && matches!(test_case.fault_type, Timeout)
                && matches!(test_case.msg, Bcast)
            {
                info!(
                    "drop bcast from party {} in round {}",
                    test_case.faulter_share_id, test_case.round
                );
                continue;
            }

            for (_, round) in rounds.iter_mut() {
                round.msg_in(round.share_to_party_id(from).unwrap(), &bytes)?;
            }
        }
    } else if current_round == test_case.round
        && matches!(test_case.msg, Bcast)
        && matches!(test_case.fault_type, Timeout)
    {
        panic!("round {} has no bcasts to drop", test_case.round);
    }

    // collect p2ps
    let all_p2ps: Option<VecMap<K, HoleVecMap<K, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().cloned())
        .collect();

    // deliver p2ps if present
    if let Some(all_p2ps) = all_p2ps {
        for (from, p2ps) in all_p2ps.into_iter() {
            for (to, bytes) in p2ps {
                // inject timeout fault
                if current_round == test_case.round
                    && test_case.faulter_share_id == from
                    && matches!(test_case.fault_type, Timeout)
                {
                    if let P2p { to: victim } = test_case.msg {
                        if victim == to {
                            info!(
                                "drop p2p from party {} to {} in round {}",
                                test_case.faulter_share_id, victim, test_case.round
                            );
                            continue;
                        }
                    }
                }

                for (_, round) in rounds.iter_mut() {
                    round.msg_in(round.share_to_party_id(from).unwrap(), &bytes)?;
                }
            }
        }
    } else if current_round == test_case.round
        && matches!(test_case.msg, P2p { to: _ })
        && matches!(test_case.fault_type, Timeout)
    {
        panic!("round {} has no p2ps to drop", test_case.round);
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
