use strum::IntoEnumIterator;

use super::{Behaviour, Behaviour::*};
use crate::protocol::gg20::keygen::{crimes::Crime, KeygenOutput};

pub(super) struct TestCaseParty {
    pub(super) behaviour: Behaviour,
    pub(super) expected_crimes: Vec<Crime>,
}

pub(super) struct TestCase {
    pub(super) threshold: usize,
    pub(super) allow_self_delivery: bool,
    pub(super) expect_success: bool,
    pub(super) parties: Vec<TestCaseParty>,
}

impl TestCase {
    pub(super) fn assert_expected_output(&self, output: &KeygenOutput) {
        match output {
            Ok(_) => assert!(self.expect_success, "expect failure, got success"),
            Err(criminals) => {
                assert!(!self.expect_success, "expect success, got failure");
                // make criminals into a Vec<&Vec<Crime>>
                let expected_crime_lists: Vec<&Vec<Crime>> =
                    self.parties.iter().map(|p| &p.expected_crimes).collect();
                assert_eq!(
                    expected_crime_lists,
                    criminals.iter().collect::<Vec<&Vec<Crime>>>()
                );
            }
        }
    }
    pub(super) fn share_count(&self) -> usize {
        self.parties.len()
    }
}

impl Behaviour {
    pub(super) fn is_honest(&self) -> bool {
        matches!(self, Honest)
    }

    /// Return the `Crime` variant `c` such that
    /// if one party acts according to `self` and all other parties are honest
    /// then honest parties will detect `c`.
    /// Panics if `self` is `Honest`
    pub(super) fn to_crime(&self) -> Crime {
        match self {
            Honest => panic!("`to_crime` called with `Honest`"),
            R1BadCommit => Crime::R3BadReveal,
            R2BadShare { victim: v } => Crime::R4FailBadVss { victim: *v },
            R2BadEncryption { victim: v } => Crime::R4FailBadEncryption { victim: *v },
            R3FalseAccusation { victim: v } => Crime::R4FailFalseAccusation { victim: *v },
        }
    }
}

// Test all basic cases with one malicious behaviour per test case
// #[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_basic_cases() -> Vec<TestCase> {
    Behaviour::iter()
        .filter(|b| !b.is_honest())
        .map(|b| TestCase {
            threshold: 1,
            allow_self_delivery: false,
            expect_success: false,
            parties: vec![
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                TestCaseParty {
                    expected_crimes: vec![b.to_crime()],
                    behaviour: b,
                },
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        })
        .collect()
}

pub(super) fn self_accusation_cases() -> Vec<TestCase> {
    vec![TestCase {
        threshold: 1,
        allow_self_delivery: false,
        expect_success: false,
        parties: vec![
            TestCaseParty {
                behaviour: Honest,
                expected_crimes: vec![],
            },
            TestCaseParty {
                behaviour: Behaviour::R3FalseAccusation { victim: 1 },
                expected_crimes: vec![Crime::R4FailFalseAccusation { victim: 1 }],
            },
            TestCaseParty {
                behaviour: Honest,
                expected_crimes: vec![],
            },
        ],
    }]
}
