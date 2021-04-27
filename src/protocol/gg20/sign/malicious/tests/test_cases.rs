// TODO: is there any way to avoid making everything pub?
use super::*;
use crate::protocol::{CrimeType, Criminal};

pub struct SignParticipant {
    pub party_index: usize,
    pub behaviour: MaliciousType,
}

pub struct TestCase {
    pub share_count: usize,
    pub threshold: usize,
    pub allow_self_delivery: bool,
    pub sign_participants: Vec<SignParticipant>,
    pub sign_expected_criminals: Vec<Criminal>,
}

use strum::IntoEnumIterator;
// generate simple test cases using strum to iterate malicious types.
// Strum fills all additional data on enum variants with Default::default()
// https://docs.rs/strum_macros/0.20.1/strum_macros/derive.EnumIter.html
// this means that all criminals in these test cases target index 0
#[rustfmt::skip] // skip formatting to make file more readable
pub fn generate_simple_test_cases() -> Vec<TestCase> {
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

// The conention we make is that self-targeting corruptions are skipped
#[rustfmt::skip] // skip formatting to make file more readable
pub fn generate_skipping_cases() -> Vec<TestCase> {
    let self_targeting_types = vec![
        R1BadProof { victim: 2 },
        R1FalseAccusation { victim: 2 },
        R2BadMta { victim: 2 },
        R2BadMtaWc { victim: 2 },
        R2FalseAccusationMta { victim: 2 },
        R2FalseAccusationMtaWc { victim: 2 },
        // R3FalseAccusation { victim: 2 }, // this produces criminals
        // R4FalseAccusation { victim: 2 }, // this produces criminals
        R5BadProof { victim: 2 },
        R5FalseAccusation { victim: 2 },
        // R6FalseAccusation { victim: 2 }, // this produces criminals
    ];

    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = true;
    for malicous_type in self_targeting_types {
        test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery,
            sign_participants: vec![
                SignParticipant { party_index: 1, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 3, behaviour: malicous_type, },
            ],
            sign_expected_criminals: vec![],
        })
    }
    test_cases
}

// TODO: Add more cases here
#[rustfmt::skip] // skip formatting to make file more readable
pub fn generate_multiple_faults() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 5, threshold: 2, allow_self_delivery: true, 
            sign_participants: vec![
                SignParticipant { party_index: 4, behaviour: Honest, },
                SignParticipant { party_index: 2, behaviour: Honest, },
                SignParticipant { party_index: 1, behaviour: R1BadProof { victim: 0 }, },
            ],
            sign_expected_criminals: vec![
                Criminal { index: 2, crime_type: CrimeType::Malicious, }
            ],
        },
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
    ]
}
