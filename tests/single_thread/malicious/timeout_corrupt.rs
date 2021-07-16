//! Single-threaded generic protocol execution
//! with a missing or corrupted message

use tofn::refactor::{
    collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
    protocol::api::{BytesVec, Fault, Protocol, TofnResult},
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

pub fn single_fault_test_case_list<K>() -> Vec<SingleFaulterTestCase<K>> {
    use self::{FaultType::*, RoundMessage::*};
    let zero = TypedUsize::from_usize(0);
    vec![
        single_fault_test_case(Bcast, Timeout),
        single_fault_test_case(P2p { victim: zero }, Timeout),
        single_fault_test_case(Bcast, Corruption),
        single_fault_test_case(P2p { victim: zero }, Corruption),
    ]
}

fn single_fault_test_case<K>(
    msg: RoundMessage<K>,
    fault_type: FaultType,
) -> SingleFaulterTestCase<K> {
    // 5 parties, faulter: 3, round: 2
    let faulter = TypedUsize::from_usize(3);
    let mut faulters = FillVecMap::with_size(5);
    let fault = match fault_type {
        FaultType::Timeout => Fault::MissingMessage,
        FaultType::Corruption => Fault::CorruptedMessage,
    };
    faulters.set(faulter, fault).unwrap();
    SingleFaulterTestCase {
        faulter,
        round: 2,
        msg,
        fault_type,
        expected_honest_output: faulters,
    }
}

pub struct SingleFaulterTestCase<K> {
    pub faulter: TypedUsize<K>, // faulter party index
    pub round: usize,           // round in which fault occurs, index starts at 1
    pub msg: RoundMessage<K>,   // which message is faulty
    pub fault_type: FaultType,  // missing or corrupted message
    pub expected_honest_output: FillVecMap<K, Fault>,
}

#[derive(Debug)]
pub enum RoundMessage<K> {
    Bcast,
    P2p { victim: TypedUsize<K> },
}

#[derive(Debug)]

pub enum FaultType {
    Timeout,
    Corruption,
}

fn execute_test_case<F, K, P>(
    parties: VecMap<K, Protocol<F, K, P>>,
    test_case: SingleFaulterTestCase<K>,
) where
    K: PartialEq + std::fmt::Debug + Clone, // TODO can't quite escape ugly trait bounds :(
{
    let parties = execute_protocol(parties, &test_case).expect("internal tofn error");

    // TEST: honest parties finished and produced the expected output
    for (i, party) in parties.iter() {
        if i != test_case.faulter {
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
    test_case: &SingleFaulterTestCase<K>,
) -> TofnResult<VecMap<K, Protocol<F, K, P>>>
where
    K: Clone,
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
    test_case: &SingleFaulterTestCase<K>,
    current_round: usize,
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

    // collect bcasts
    let bcasts: Option<VecMap<K, BytesVec>> = rounds
        .iter()
        .map(|(_, round)| round.bcast_out().cloned())
        .collect();

    // deliver bcasts if present
    if let Some(bcasts) = bcasts {
        for (from, mut bytes) in bcasts.into_iter() {
            // inject fault
            if current_round == test_case.round
                && matches!(test_case.msg, RoundMessage::Bcast)
                && test_case.faulter == from
            {
                match test_case.fault_type {
                    FaultType::Timeout => {
                        info!(
                            "drop bcast from party {} in round {}",
                            test_case.faulter, test_case.round
                        );
                        continue;
                    }
                    FaultType::Corruption => {
                        info!(
                            "corrupt bcast from party {} in round {}",
                            test_case.faulter, test_case.round
                        );
                        bytes = b"these bytes are corrupted 1234".to_vec()
                    }
                }
            }

            for (_, round) in rounds.iter_mut() {
                round.bcast_in(from, &bytes)?;
            }
        }
    } else if current_round == test_case.round && matches!(test_case.msg, RoundMessage::Bcast) {
        panic!("round {} has no bcasts to fault", test_case.round);
    }

    // collect p2ps
    let all_p2ps: Option<VecMap<K, HoleVecMap<K, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().cloned())
        .collect();

    // deliver p2ps if present
    if let Some(all_p2ps) = all_p2ps {
        for (from, p2ps) in all_p2ps.into_iter() {
            for (to, mut bytes) in p2ps {
                // inject fault
                if current_round == test_case.round {
                    if let RoundMessage::P2p { victim } = test_case.msg {
                        if test_case.faulter == from && victim == to {
                            match test_case.fault_type {
                                FaultType::Timeout => {
                                    info!(
                                        "drop p2p from party {} to {} in round {}",
                                        test_case.faulter, victim, test_case.round
                                    );
                                    continue;
                                }
                                FaultType::Corruption => {
                                    info!(
                                        "corrupt p2p from party {} to {} in round {}",
                                        test_case.faulter, victim, test_case.round
                                    );
                                    bytes = b"these bytes are corrupted 1234".to_vec()
                                }
                            }
                        }
                    }
                }

                for (_, round) in rounds.iter_mut() {
                    round.p2p_in(from, to, &bytes)?;
                }
            }
        }
    } else if current_round == test_case.round
        && matches!(test_case.msg, RoundMessage::P2p { victim: _ })
    {
        panic!("round {} has no p2ps to fault", test_case.round);
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
