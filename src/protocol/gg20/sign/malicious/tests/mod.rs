use super::*;
use crate::protocol::{gg20::keygen::tests::execute_keygen, tests::execute_protocol_vec, Protocol};
use tracing_test::traced_test; // enable logs in tests

static MESSAGE_TO_SIGN: [u8; 2] = [42, 24];

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
    static ref SKIPPING_CASES: Vec<TestCase> = generate_skipping_cases();
    static ref SAME_ROUND_CASES: Vec<TestCase> = generate_multiple_faults_in_same_round();
    static ref MULTIPLE_VICTIMS: Vec<TestCase> = generate_target_multiple_parties();
    static ref MULTIPLE_FAULTS: Vec<TestCase> = generate_multiple_faults();
    static ref PANIC_THRESHOLD: Vec<TestCase> = generate_small_threshold();
    static ref PANIC_INDEX: Vec<TestCase> = generate_out_of_index();
}

#[test]
#[traced_test]
fn basic_tests() {
    execute_test_case_list(&BASIC_CASES);
}

#[test]
#[traced_test]
fn skipping_cases() {
    execute_test_case_list(&SKIPPING_CASES);
}

#[test]
#[traced_test]
fn same_round_cases() {
    execute_test_case_list(&SAME_ROUND_CASES);
}

#[test]
#[traced_test]
fn multiple_targets_cases() {
    execute_test_case_list(&MULTIPLE_VICTIMS);
}

#[test]
#[traced_test]
fn multiple_faults() {
    execute_test_case_list(&MULTIPLE_FAULTS);
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

fn execute_test_case_list(test_cases: &[test_cases::TestCase]) {
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

fn execute_test_case(t: &test_cases::TestCase) {
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

    // TEST: honest parties finished and correctly computed the criminals list
    for signer in signers
        .iter()
        .filter(|s| matches!(s.malicious_type, Honest))
    {
        let output = signer.sign.final_output.clone().unwrap_or_else(|| {
            panic!(
                "honest participant {} did not finish",
                signer.sign.my_participant_index
            )
        });
        t.assert_expected_output(&output);
    }
}
