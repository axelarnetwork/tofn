use strum::IntoEnumIterator;

use super::*;
use crate::protocol::gg20::sign::{crimes::Crime, SignOutput2};

pub(super) struct SignParticipant {
    pub(super) party_index: usize,
    pub(super) behaviour: MaliciousType,
    pub(super) expected_crimes: Vec<Crime>,
}

pub(super) struct TestCase {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) allow_self_delivery: bool,
    pub(super) expect_success: bool,
    pub(super) sign_participants: Vec<SignParticipant>,
}

impl TestCase {
    pub(super) fn assert_expected_output(&self, output: &SignOutput2) {
        match output {
            Ok(_) => assert!(self.expect_success, "expect failure, got success"),
            Err(criminals) => {
                assert!(!self.expect_success, "expect success, got failure");
                // make criminals into a Vec<&Vec<Crime>>
                let expected_crime_lists: Vec<&Vec<Crime>> = self
                    .sign_participants
                    .iter()
                    .map(|p| &p.expected_crimes)
                    .collect();
                assert_eq!(
                    expected_crime_lists,
                    criminals.iter().collect::<Vec<&Vec<Crime>>>()
                );
            }
        }
    }
}

pub(super) fn map_type_to_crime(t: &MaliciousType) -> Vec<Crime> {
    match t {
        Honest => vec![],
        R1BadProof { victim: v } => vec![Crime::R3FailBadRangeProof { victim: *v }],
        R2FalseAccusation { victim: v } => vec![Crime::R3FailFalseAccusation { victim: *v }],
        R2BadMta { victim: v } => vec![Crime::R4FailBadRangeProof { victim: *v }],
        R2BadMtaWc { victim: v } => vec![Crime::R4FailBadRangeProof { victim: *v }],
        R3FalseAccusationMta { victim: v } => vec![Crime::R4FailFalseAccusation { victim: *v }],
        R3FalseAccusationMtaWc { victim: v } => vec![Crime::R4FailFalseAccusation { victim: *v }],
        R3BadProof => vec![Crime::R4BadPedersenProof],
        R4BadReveal => vec![Crime::R5BadHashCommit],
        R5BadProof { victim: v } => vec![Crime::R7FailBadRangeProof { victim: *v }],
        R6FalseAccusation { victim: v } => vec![Crime::R7FailFalseAccusation { victim: *v }],
        R6BadProof => vec![Crime::R7BadRangeProof],
        R7BadSigSummand => vec![Crime::R8BadSigSummand],
        R3BadNonceXBlindSummand => vec![Crime::R8FailRandomizerBadNonceXBlindSummand],
        R3BadEcdsaNonceSummand => vec![Crime::R8FailRandomizerBadNonceSummand],
        R1BadSecretBlindSummand => vec![Crime::R8FailRandomizerBadBlindSummand],
        R3BadMtaBlindSummandRhs { victim: v } => {
            vec![Crime::R8FailRandomizerMtaBlindSummandRhs { victim: *v }]
        }
        R3BadMtaBlindSummandLhs { victim: v } => {
            vec![Crime::R8FailRandomizerMtaBlindSummandLhs { victim: *v }]
        }
        R6FalseFailRandomizer => vec![Crime::R8FailRandomizerFalseComplaint],
    }
}

// Test all basic cases with one malicious behaviour per test case
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_basic_cases() -> Vec<TestCase> {
    let mut basic_test_cases = vec![];
    let share_count= 5;
    let threshold= 2;
    let allow_self_delivery= false;
    let expect_success = false;
    for m in MaliciousType::iter().skip(1) {
        basic_test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery, expect_success,
            sign_participants: vec![
                SignParticipant {
                    party_index: 4, behaviour: Honest, expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 3, expected_crimes: map_type_to_crime(&m), behaviour: m,
                },
                SignParticipant {
                    party_index: 2, behaviour: Honest, expected_crimes: vec![],
                },
            ],
        })
    }
    basic_test_cases
}

// Test all cases where malicious behaviours are skipped due to self-targeting
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_skipping_cases_2() -> Vec<TestCase> {
    let victim = 2; // all victims are at index 2
    let self_targeting_types = vec![
        R1BadProof { victim },
        // R2FalseAccusation { victim }, // this produces criminals
        R2BadMta { victim },
        R2BadMtaWc { victim },
        // R3FalseAccusationMta { victim }, // this produces criminals
        // R3FalseAccusationMtaWc { victim }, // this produces criminals
        R3BadMtaBlindSummandLhs { victim },
        R3BadMtaBlindSummandRhs { victim },
        // R5FalseAccusation { victim }, // this produces criminals
        R5BadProof { victim },
        // R6FalseAccusation { victim }, // this produces criminals
        // R7FalseAccusation { victim }, // this produces criminals
    ];

    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = false;
    let expect_success = true;
    for t in self_targeting_types {
        test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery, expect_success,
            sign_participants: vec![
                SignParticipant { party_index: 1, behaviour: Honest, expected_crimes: vec![]}, // index 0
                SignParticipant { party_index: 2, behaviour: Honest, expected_crimes: vec![]}, // index 1
                // all malicious parties are at index 2 and are targeting themselves 
                SignParticipant { party_index: 3, behaviour: t, expected_crimes: vec![]}, // index 2
            ],
        })
    }
    test_cases
}

pub(super) fn generate_multiple_faults_in_same_round_2() -> Vec<TestCase> {
    // list all bad behaviours per round
    // I wish all faults of the round X would have a common prefix R'X' so I could use
    // let r1_faults = MaliciousType:iter().filter(|type| type.contains("R1"));
    // instead of manually listing them
    let victim = 0;
    let all_rounds_faults = vec![
        // round 1 faults
        vec![R1BadProof { victim }, R2FalseAccusation { victim }],
        // round 2 faults
        vec![
            R2BadMta { victim },
            R2BadMtaWc { victim },
            R3FalseAccusationMta { victim },
            R3FalseAccusationMtaWc { victim },
        ],
        // round 3 faults
        vec![R3BadProof],
        // round 4 faults
        vec![R4BadReveal],
        // round 5 faults
        vec![R5BadProof { victim }, R6FalseAccusation { victim }],
        // round 6 faults
        vec![R6BadProof],
        // round 7 faults
        vec![R7BadSigSummand],
    ];


    // create test cases for all rounds
    let mut test_cases = Vec::new();
    for round_faults in all_rounds_faults {
        // start with the victim at pos 0
        let mut participants = vec![
            SignParticipant {
                party_index: round_faults.len(), // give the good guy the last party index
                behaviour: Honest, 
                expected_crimes: vec![],
            },
        ];
        for (i, fault) in round_faults.into_iter().enumerate() {
            participants.push(
                // I have to state `expected_crimes` before `behaviour` because
                // the later consumes `fault` and I cannot borrow it after that
                // wonder if rust compiler could accomodate that
                SignParticipant {
                    party_index: i,
                    expected_crimes: map_type_to_crime(&fault),
                    behaviour: fault, // behaviour data initialized by Default:default()
                },
            );
        }
        test_cases.push(TestCase {
            share_count: 5,
            threshold: participants.len() - 1, // threshold < #parties
            allow_self_delivery: true,
            expect_success: false,
            sign_participants: participants,
        });
    }
    test_cases
}

