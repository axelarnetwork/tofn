use strum::IntoEnumIterator;

use super::*;
use crate::protocol::gg20::sign::crimes::Crime;

pub(super) struct SignParticipant {
    pub(super) party_index: usize,
    pub(super) behaviour: MaliciousType,
    pub(super) expected_crimes: Vec<Crime>,
}

pub(super) struct TestCase {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) allow_self_delivery: bool,
    pub(super) sign_participants: Vec<SignParticipant>,
}

pub(super) fn map_type_to_crime(t: &MaliciousType) -> Vec<Crime> {
    match t {
        Honest => vec![],
        R1BadProof { victim: v } => vec![Crime::R3BadRangeProof { victim: *v }],
        R2FalseAccusation { victim: v } => vec![Crime::R3FalseAccusation { victim: *v }],
        R2BadMta { victim: v } => vec![Crime::R4BadRangeProof { victim: *v }],
        R2BadMtaWc { victim: v } => vec![Crime::R4BadRangeProof { victim: *v }],
        R3FalseAccusationMta { victim: v } => vec![Crime::R4FalseAccusation { victim: *v }],
        R3FalseAccusationMtaWc { victim: v } => vec![Crime::R4FalseAccusation { victim: *v }],
        R3BadProof => vec![Crime::R5BadRangeProof],
        R4FalseAccusation { victim: v } => vec![Crime::R5FalseAccusation { victim: *v }],
        R4BadReveal => vec![Crime::R6BadHashCommit],
        R5FalseAccusation { victim: v } => vec![Crime::R6FalseAccusation { victim: *v }],
        R5BadProof { victim: v } => vec![Crime::R7BadRangeProof { victim: *v }],
        R6FalseAccusation { victim: v } => vec![Crime::R7FalseAccusation { victim: *v }],
        R6BadProof => vec![Crime::R8BadRangeProof],
        R7FalseAccusation { victim: v } => vec![Crime::R8FalseAccusation { victim: *v }],
        // TODO: is this correct?
        R7BadSigSummand => vec![Crime::R8MissingData],
        R3BadNonceXBlindSummand => vec![Crime::R8BadNonceXBlindSummand],
        R3BadEcdsaNonceSummand => vec![Crime::R8BadNonceSummand],
        R1BadSecretBlindSummand => vec![Crime::R8BadBlindSummand],
        R3BadMtaBlindSummandRhs { victim: v } => vec![Crime::R8MtaBlindSummandRhs { victim: *v }],
        R3BadMtaBlindSummandLhs { victim: v } => vec![Crime::R8MtaBlindSummandLhs { victim: *v }],
        R6FalseFailRandomizer => vec![Crime::R8FalseComplaint],
    }
}

// Test all basic cases with one malicious behaviour per test case
#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_basic_cases() -> Vec<TestCase> {
    let mut basic_test_cases = vec![];
    let share_count= 5;
    let threshold= 2;
    let allow_self_delivery= false;
    for t in MaliciousType::iter() {
        basic_test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery,
            sign_participants: vec![
                SignParticipant {
                    party_index: 4, behaviour: Honest, expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 3, expected_crimes: map_type_to_crime(&t), behaviour: t,
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
        R2FalseAccusation { victim },
        R2BadMta { victim },
        R2BadMtaWc { victim },
        R3FalseAccusationMta { victim },
        R3FalseAccusationMtaWc { victim },
        R3BadMtaBlindSummandLhs { victim },
        // R3FalseAccusation { victim }, // this produces criminals
        // R4FalseAccusation { victim }, // this produces criminals
        R5BadProof { victim },
        R6FalseAccusation { victim },
        // R6FalseAccusation { victim }, // this produces criminals
    ];

    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = false;
    for t in self_targeting_types {
        test_cases.push(TestCase {
            share_count, threshold, allow_self_delivery,
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
