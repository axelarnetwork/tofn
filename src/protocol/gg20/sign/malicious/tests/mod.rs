use super::*;
use crate::protocol::{gg20::keygen::tests::execute_keygen, tests::execute_protocol_vec, Protocol};
use tracing_test::traced_test; // enable logs in tests

// mod test_cases;
// use test_cases::*;

// lazy_static::lazy_static! {
//     static ref SIMPLE_TEST_CASES: Vec<TestCase> = generate_simple_test_cases();
//     static ref SELF_TARGET_TEST_CASES: Vec<TestCase> = generate_skipping_cases();
//     static ref MULTIPLE_IN_SAME_ROUND: Vec<TestCase> = generate_multiple_faults_in_same_round();
//     static ref TEST_CASES: Vec<TestCase> = generate_multiple_faults();
//     static ref TARGET_MULTIPLE: Vec<TestCase> = generate_target_multiple_parties();
//     static ref PANIC_THRESHOLD: Vec<TestCase> = generate_small_threshold();
//     static ref PANIC_INDEX: Vec<TestCase> = generate_out_of_index();
// }

static MESSAGE_TO_SIGN: [u8; 2] = [42, 24];

// #[test]
// #[traced_test]
// fn gus() {
//     use crate::protocol::{CrimeType, Criminal};
//     execute_test_case(&TestCase {
//         share_count: 5,
//         threshold: 2,
//         allow_self_delivery: true,
//         sign_participants: vec![
//             SignParticipant {
//                 party_index: 0,
//                 behaviour: Honest,
//             },
//             SignParticipant {
//                 party_index: 1,
//                 behaviour: Honest,
//             },
//             SignParticipant {
//                 party_index: 2,
//                 behaviour: R3BadProof,
//             }, // initialize enum values with Default::default()
//         ],
//         sign_expected_criminals: vec![Criminal {
//             index: 2,
//             crime_type: CrimeType::Malicious,
//         }],
//     });
// }

// #[test]
// #[traced_test]
// fn simple_cases() {
//     execute_test_case_list(&SIMPLE_TEST_CASES);
// }

// #[test]
// #[traced_test]
// fn self_targeting() {
//     execute_test_case_list(&SELF_TARGET_TEST_CASES);
// }

// #[test]
// #[traced_test]
// fn multiple_faults_in_same_round() {
//     execute_test_case_list(&MULTIPLE_IN_SAME_ROUND);
// }

// #[test]
// #[traced_test]
// fn multiple_faults() {
//     execute_test_case_list(&TEST_CASES);
// }

// #[test]
// #[traced_test]
// fn target_multiple_parties() {
//     execute_test_case_list(&TARGET_MULTIPLE);
// }
// #[test]
// #[should_panic]
// fn panic_small_threshold() {
//     execute_test_case_list(&PANIC_THRESHOLD);
// }

// #[test]
// #[should_panic]
// fn panic_out_of_index() {
//     execute_test_case_list(&PANIC_INDEX);
// }

// fn execute_test_case_list(test_cases: &[TestCase]) {
//     for t in test_cases {
//         let malicious_count = t
//             .sign_participants
//             .iter()
//             .filter(|p| !matches!(p.behaviour, Honest))
//             .count();
//         info!(
//             "malicious_count [{}] share_count [{}] threshold [{}]",
//             malicious_count, t.share_count, t.threshold
//         );
//         execute_test_case(t);
//     }
// }

// fn execute_test_case(t: &TestCase) {
//     let participant_indices: Vec<usize> =
//         t.sign_participants.iter().map(|p| p.party_index).collect();
//     let key_shares = execute_keygen(t.share_count, t.threshold);

//     let mut signers: Vec<BadSign> = t
//         .sign_participants
//         .iter()
//         .map(|p| {
//             BadSign::new(
//                 &key_shares[p.party_index],
//                 &participant_indices,
//                 &MESSAGE_TO_SIGN,
//                 p.behaviour.clone(),
//             )
//             .unwrap()
//         })
//         .collect();

//     let mut protocols: Vec<&mut dyn Protocol> =
//         signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

//     execute_protocol_vec(&mut protocols, t.allow_self_delivery);

//     // TEST: honest parties finished and correctly computed the criminals list
//     for signer in signers
//         .iter()
//         .filter(|s| matches!(s.malicious_type, Honest))
//     {
//         let output = signer.clone_output().unwrap_or_else(|| {
//             panic!(
//                 "honest participant {} did not finish",
//                 signer.sign.my_participant_index
//             )
//         });
//         // in some cases the protocol succeeds despite malicious behaviour
//         // example: self-victimizing adversaries
//         // in these cases, we expect an empty criminals list
//         let criminals = match output {
//             Ok(_) => vec![],
//             Err(criminals) => criminals,
//         };
//         assert_eq!(
//             criminals, t.sign_expected_criminals,
//             "honest participant {} unexpected criminals list:\n   got: {:?}\nexpect: {:?}",
//             signer.sign.my_participant_index, criminals, t.sign_expected_criminals
//         );
//     }
// }

mod test_cases2;

lazy_static::lazy_static! {
    static ref BASIC_CASES_2: Vec<test_cases2::TestCase> = test_cases2::generate_basic_cases();
    static ref SKIPPING_CASES_2: Vec<test_cases2::TestCase> = test_cases2::generate_skipping_cases_2();
    static ref SAME_ROUND_CASES_2: Vec<test_cases2::TestCase> = test_cases2::generate_multiple_faults_in_same_round_2();
    static ref MULTIPLE_VICTIMS_2: Vec<test_cases2::TestCase> = test_cases2::generate_target_multiple_parties_2();
    static ref MULTIPLE_FAULTS_2: Vec<test_cases2::TestCase> = test_cases2::generate_multiple_faults_2();
    static ref PANIC_THRESHOLD_2: Vec<test_cases2::TestCase> = test_cases2::generate_small_threshold_2();
    static ref PANIC_INDEX_2: Vec<test_cases2::TestCase> = test_cases2::generate_out_of_index_2();
}

#[test]
#[traced_test]
fn basic_tests_2() {
    execute_test_case_list_2(&BASIC_CASES_2);
}

#[test]
#[traced_test]
fn skipping_cases_2() {
    execute_test_case_list_2(&SKIPPING_CASES_2);
}

#[test]
#[traced_test]
fn same_round_cases_2() {
    execute_test_case_list_2(&SAME_ROUND_CASES_2);
}

#[test]
#[traced_test]
fn multiple_targets_cases_2() {
    execute_test_case_list_2(&MULTIPLE_VICTIMS_2);
}

#[test]
#[traced_test]
fn multiple_faults_2() {
    execute_test_case_list_2(&MULTIPLE_FAULTS_2);
}

#[test]
#[should_panic]
fn panic_small_threshold_2() {
    execute_test_case_list_2(&PANIC_THRESHOLD_2);
}

#[test]
#[should_panic]
fn panic_out_of_index_2() {
    execute_test_case_list_2(&PANIC_INDEX_2);
}

fn execute_test_case_list_2(test_cases: &[test_cases2::TestCase]) {
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
