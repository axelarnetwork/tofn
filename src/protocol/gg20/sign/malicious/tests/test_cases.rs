use super::*;
use crate::protocol::{CrimeType, Criminal};

pub(super) struct SignParticipant {
    pub(super) party_index: usize,
    pub(super) behaviour: MaliciousType,
}

pub(super) struct TestCase {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) allow_self_delivery: bool,
    pub(super) sign_participants: Vec<SignParticipant>,
    pub(super) sign_expected_criminals: Vec<Criminal>,
}

use strum::IntoEnumIterator;
// generate simple test cases using strum to iterate malicious types.
// Strum fills all additional data on enum variants with Default::default()
// https://docs.rs/strum_macros/0.20.1/strum_macros/derive.EnumIter.html
// this means that all criminals in these test cases target index 0
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_simple_test_cases() -> Vec<TestCase> {
    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = true;
    // skip honest bahaviour
    for malicous_type in MaliciousType::iter().skip(1) {
        test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery,
            sign_participants: vec![
                SignParticipant { party_index: 1, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: malicous_type, }, // initialize enum values with Default::default() 
            ],
            sign_expected_criminals: vec![
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        })
    }
    test_cases
}

// Test all cases where malicious behaviours are skipped due to self-targeting
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_skipping_cases() -> Vec<TestCase> {
    let victim = 2; // all victims are at index 2
    let self_targeting_types = vec![
        R1BadProof { victim },
        R1FalseAccusation { victim },
        R2BadMta { victim },
        R2BadMtaWc { victim },
        R2FalseAccusationMta { victim },
        R2FalseAccusationMtaWc { victim },
        // R3FalseAccusation { victim }, // this produces criminals
        // R4FalseAccusation { victim }, // this produces criminals
        R5BadProof { victim },
        R5FalseAccusation { victim },
        // R6FalseAccusation { victim }, // this produces criminals
    ];

    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = true;
    for malicous_type in self_targeting_types {
        test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery,
            sign_participants: vec![
                SignParticipant { party_index: 1, behaviour: Honest, }, // index 0
                SignParticipant { party_index: 2, behaviour: Honest, }, // index 1
                // all malicious parties are at index 2 and are targeting themselves 
                SignParticipant { party_index: 3, behaviour: malicous_type, }, // index 2
            ],
            sign_expected_criminals: vec![],
        })
    }
    test_cases
}

#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_multiple_faults_in_same_round() -> Vec<TestCase> {
    vec![
        // multiple faults in round 1
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: true, 
            sign_participants: vec![
                SignParticipant { party_index: 4, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: R1BadProof { victim: 0 }, },
                SignParticipant { party_index: 2, behaviour: R1FalseAccusation{ victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 2
        TestCase {
            share_count: 5, threshold: 4, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R2BadMta{victim: 0}, },
                SignParticipant { party_index: 2, behaviour: R2BadMtaWc{victim: 0}, },
                SignParticipant { party_index: 3, behaviour: R2FalseAccusationMta{victim: 0}, },
                SignParticipant { party_index: 4, behaviour: R2FalseAccusationMtaWc{victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
                Criminal { index: 3, crime_type: CrimeType::Malicious, },
                Criminal { index: 4, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 3
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R3BadProof, },
                SignParticipant { party_index: 2, behaviour: R3FalseAccusation{victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 4
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R4BadReveal, },
                SignParticipant { party_index: 2, behaviour: R4FalseAccusation{victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 5
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R5BadProof{victim: 0}, },
                SignParticipant { party_index: 2, behaviour: R5FalseAccusation{victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 6
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R6BadProof, },
                SignParticipant { party_index: 2, behaviour: R6FalseAccusation{victim: 0}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
                Criminal { index: 2, crime_type: CrimeType::Malicious, },
            ],
        },
        // multiple faults in round 7
        TestCase {
            share_count: 5, threshold: 1, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R7BadSigSummand, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
            ],
        },
    ]
}

#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_target_multiple_parties() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 9, threshold: 6, allow_self_delivery: true, 
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: R1BadProof { victim: 0 }, },
                SignParticipant { party_index: 4, behaviour: R1FalseAccusation{ victim: 0}, },
                SignParticipant { party_index: 5, behaviour: R1BadProof { victim: 1 }, },
                SignParticipant { party_index: 6, behaviour: R1FalseAccusation{ victim: 1}, },
                // R5 should not be registered because they happen after R1 crimes
                SignParticipant { party_index: 7, behaviour: R5BadProof { victim: 2 }, },       
                SignParticipant { party_index: 8, behaviour: R5FalseAccusation{ victim: 2}, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 3, crime_type: CrimeType::Malicious, },
                Criminal { index: 4, crime_type: CrimeType::Malicious, },
                Criminal { index: 5, crime_type: CrimeType::Malicious, },
                Criminal { index: 6, crime_type: CrimeType::Malicious, },
            ],
        },
    ]
}

#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_multiple_faults() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 5, threshold: 4, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R1BadProof { victim: 2 }, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: R3BadProof, },
                SignParticipant { party_index: 4, behaviour: Honest, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
            ],
        },
        TestCase {
            share_count: 10, threshold: 4, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: R1BadProof { victim: 3 }, },
                SignParticipant { party_index: 1, behaviour: R2BadMta{victim: 3}, },
                SignParticipant { party_index: 2, behaviour: R3BadProof, },
                SignParticipant { party_index: 3, behaviour: Honest, },
                SignParticipant { party_index: 4, behaviour: R4BadReveal, },
                SignParticipant { party_index: 5, behaviour: R5BadProof{victim: 3}, },
                SignParticipant { party_index: 6, behaviour: R6BadProof, },
                SignParticipant { party_index: 7, behaviour: R7BadSigSummand, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 0, crime_type: CrimeType::Malicious, },
            ],
        },
        TestCase {
            share_count: 10, threshold: 4, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R1BadProof { victim: 0 }, },
                SignParticipant { party_index: 2, behaviour: R2BadMta{victim: 1}, },
                SignParticipant { party_index: 3, behaviour: R3BadProof, },
                SignParticipant { party_index: 4, behaviour: R4BadReveal, },
                SignParticipant { party_index: 5, behaviour: R5BadProof{victim: 3}, },
                SignParticipant { party_index: 6, behaviour: R6BadProof, },
                SignParticipant { party_index: 7, behaviour: R7BadSigSummand, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 1, crime_type: CrimeType::Malicious, },
            ],
        },
    ]
}

// Threshold is equal to the number of participants
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_small_threshold() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 5, threshold: 4, allow_self_delivery: false, // panic: threashold is 4, signers are 4
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: Honest, },
            ],
            sign_expected_criminals: vec![],
        },
    ]
}

// Target a party that does not exist
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_out_of_index() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 5, threshold: 4, allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant { party_index: 0, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 5, behaviour: Honest, }, // panic: index is equal to share_counts
            ],
            sign_expected_criminals: vec![],
        },
    ]
}
