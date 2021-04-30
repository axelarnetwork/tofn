use super::*;
use crate::protocol::{gg20::keygen::tests::execute_keygen, tests::execute_protocol_vec, Protocol};
use tracing_test::traced_test; // enable logs in tests

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref SIMPLE_TEST_CASES: Vec<TestCase> = generate_simple_test_cases();
    static ref SELF_TARGET_TEST_CASES: Vec<TestCase> = generate_skipping_cases();
    static ref MULTIPLE_IN_SAME_ROUND: Vec<TestCase> = generate_multiple_faults_in_same_round();
    static ref TEST_CASES: Vec<TestCase> = generate_multiple_faults();
    static ref TARGET_MULTIPLE: Vec<TestCase> = generate_target_multiple_parties();
    static ref PANIC_THRESHOLD: Vec<TestCase> = generate_small_threshold();
    static ref PANIC_INDEX: Vec<TestCase> = generate_out_of_index();
}

static MESSAGE_TO_SIGN: [u8; 2] = [42, 24];

#[test]
#[traced_test]
fn simple_cases() {
    execute_test_case_list(&SIMPLE_TEST_CASES);
}

#[test]
#[traced_test]
fn self_targeting() {
    execute_test_case_list(&SELF_TARGET_TEST_CASES);
}

#[test]
#[traced_test]
fn multiple_faults_in_same_round() {
    execute_test_case_list(&MULTIPLE_IN_SAME_ROUND);
}

#[test]
#[traced_test]
fn multiple_faults() {
    execute_test_case_list(&TEST_CASES);
}

#[test]
#[traced_test]
fn target_multiple_parties() {
    execute_test_case_list(&TARGET_MULTIPLE);
}
#[test]
#[should_panic]
fn panic_small_threshold() {
    execute_test_case_list(&PANIC_THRESHOLD);
}

#[test]
#[should_panic]
fn panic_out_of_index() {
    execute_test_case_list(&PANIC_INDEX);
}

fn execute_test_case_list(test_cases: &[TestCase]) {
    for t in test_cases {
        let malicious_count = t
            .sign_participants
            .iter()
            .filter(|p| !matches!(p.behaviour, Honest))
            .count();
        info!(
            "malicious_count [{}] share_count [{}] threshold [{}]",
            malicious_count, t.share_count, t.threshold
        );
        execute_test_case(t);
    }
}

fn execute_test_case(t: &TestCase) {
    let participant_indices: Vec<usize> =
        t.sign_participants.iter().map(|p| p.party_index).collect();
    let key_shares = execute_keygen(t.share_count, t.threshold);

    let mut signers: Vec<BadSign> = t
        .sign_participants
        .iter()
        .map(|p| {
            BadSign::new(
                &key_shares[p.party_index],
                &participant_indices,
                &MESSAGE_TO_SIGN,
                p.behaviour.clone(),
            )
            .unwrap()
        })
        .collect();

    let mut protocols: Vec<&mut dyn Protocol> =
        signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

    execute_protocol_vec(&mut protocols, t.allow_self_delivery);

    // TEST: everyone correctly computed the culprit list
    for signer in signers {
        // We also need to take valid output into account because we skip some
        // self-targeting malicious behaviours, resulting to valid SignOutput
        let criminals = match signer.clone_output().unwrap() {
            Ok(_) => vec![],
            Err(criminals) => criminals,
        };
        assert_eq!(criminals, t.sign_expected_criminals);
    }
}

mod test_cases2;
use crate::protocol::gg20::sign::crimes::Crime;

lazy_static::lazy_static! {
    static ref SOME_TEST_CASES: Vec<test_cases2::TestCase> = test_cases2::generate_some_test_cases();
}

#[test]
#[traced_test]
fn some_cases() {
    execute_test_case_list2(&SOME_TEST_CASES);
}

fn execute_test_case_list2(test_cases: &[test_cases2::TestCase]) {
    for t in test_cases {
        let malicious_count = t
            .sign_participants
            .iter()
            .filter(|p| !matches!(p.behaviour, Honest))
            .count();
        info!(
            "malicious_count [{}] share_count [{}] threshold [{}]",
            malicious_count, t.share_count, t.threshold
        );
        execute_test_case2(t);
    }
}

fn execute_test_case2(t: &test_cases2::TestCase) {
    let participant_indices: Vec<usize> =
        t.sign_participants.iter().map(|p| p.party_index).collect();
    let key_shares = execute_keygen(t.share_count, t.threshold);

    let mut signers: Vec<BadSign> = t
        .sign_participants
        .iter()
        .map(|p| {
            BadSign::new(
                &key_shares[p.party_index],
                &participant_indices,
                &MESSAGE_TO_SIGN,
                p.behaviour.clone(),
            )
            .unwrap()
        })
        .collect();

    let mut protocols: Vec<&mut dyn Protocol> =
        signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

    execute_protocol_vec(&mut protocols, t.allow_self_delivery);

    // TEST: everyone correctly computed the culprit list
    let expected_crime_lists: Vec<&Vec<Crime>> = t
        .sign_participants
        .iter()
        .map(|p| &p.expected_crimes)
        .collect();
    for signer in signers {
        // lots of cruft needed to get a Vec<&Vec<Crime>> to compare against expected_crime_lists
        let actual_crime_lists: Vec<&Vec<Crime>> = signer
            .sign
            .final_output2
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap_err()
            .iter()
            .map(|v| v)
            .collect();
        assert_eq!(actual_crime_lists, expected_crime_lists);
    }
}
