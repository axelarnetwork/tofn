use strum::IntoEnumIterator;

use super::{Behaviour, Behaviour::*};
use crate::protocol::gg20::{
    keygen::{crimes::Crime, KeygenOutput, MsgType, Status},
    GeneralCrime,
};

pub(super) struct TestCaseParty {
    pub(super) behaviour: Behaviour,
    pub(super) expected_crimes: Vec<Crime>,
}

pub(super) struct TestCase {
    pub(super) threshold: usize,
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

pub(super) struct StallTestCaseParty {
    pub(super) behaviour: Behaviour,
    pub(super) expected_crimes: Vec<GeneralCrime>,
}

pub(super) struct StallTestCase {
    pub(super) threshold: usize,
    pub(super) parties: Vec<StallTestCaseParty>,
}

impl StallTestCase {
    pub(crate) fn share_count(&self) -> usize {
        self.parties.len()
    }
    pub(crate) fn assert_expected_waiting_on(&self, output: &[Vec<GeneralCrime>]) {
        let mut expected_output = vec![];
        for p in &self.parties {
            expected_output.push(p.expected_crimes.clone());
        }
        assert_eq!(output, expected_output);
    }
}

impl Behaviour {
    pub(super) fn is_honest(&self) -> bool {
        matches!(self, Honest)
    }

    pub(super) fn is_spoofer(&self) -> bool {
        matches!(
            self,
            UnauthenticatedSender {
                victim: _,
                status: _
            }
        )
    }

    pub(super) fn is_staller(&self) -> bool {
        matches!(self, Stall { msg_type: _ })
    }

    /// Return the `Crime` variant `c` such that
    /// if one party acts according to `self` and all other parties are honest
    /// then honest parties will detect `c`.
    /// Panics if `self` is `Honest`
    pub(super) fn to_crime(&self) -> Crime {
        match self {
            Honest => panic!("`to_crime` called with `Honest`"),
            Stall { msg_type: _ } => panic!("`to_crime` called with `Stall`"),
            UnauthenticatedSender {
                victim: v,
                status: s,
            } => Crime::SpoofedMessage {
                victim: *v,
                status: s.clone(),
            },
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
        .filter(|b| !b.is_honest() && !b.is_spoofer() && !b.is_staller())
        .map(|b| TestCase {
            threshold: 1,
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

// create a spoofer that acts before the original sender and gets discovered
pub(super) fn generate_spoof_before_honest_cases() -> Vec<TestCase> {
    let spoofers = Status::iter()
        .filter(|s| {
            !matches!(
                s,
                Status::New | Status::Done | Status::Fail | Status::R3Fail
            )
        })
        .map(|s| UnauthenticatedSender {
            victim: 1,
            status: s,
        })
        .collect::<Vec<Behaviour>>();

    spoofers
        .iter()
        .map(|spoofer| TestCase {
            threshold: 1,
            expect_success: false,
            parties: vec![
                TestCaseParty {
                    behaviour: spoofer.clone(),
                    expected_crimes: vec![spoofer.to_crime()],
                },
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        })
        .collect()
}

// create a spoofer that acts after the original sender and gets discovered
pub(super) fn generate_spoof_after_honest_cases() -> Vec<TestCase> {
    let spoofers = Status::iter()
        .filter(|s| matches!(s, Status::R1 | Status::R2 | Status::R3)) // match outputs of spoofer::is_spoof_round()
        .map(|s| UnauthenticatedSender {
            victim: 0,
            status: s,
        })
        .collect::<Vec<Behaviour>>();

    spoofers
        .iter()
        .map(|spoofer| TestCase {
            threshold: 1,
            expect_success: false,
            parties: vec![
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                TestCaseParty {
                    behaviour: spoofer.clone(),
                    expected_crimes: vec![spoofer.to_crime()],
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

fn map_staller_to_crime(staller: &Behaviour) -> GeneralCrime {
    let msg_type = match staller {
        Stall { msg_type } => msg_type,
        _ => panic!("Mapping non-stall behaviour to stall crime"),
    };
    GeneralCrime::Stall {
        msg_type: crate::protocol::gg20::GeneralMsgType::KeygenMsgType {
            msg_type: msg_type.clone(),
        },
    }
}

// create stallers
pub(super) fn generate_stall_cases() -> Vec<StallTestCase> {
    use MsgType::*;
    let stallers = MsgType::iter()
        .filter(|msg_type| matches!(msg_type, R1Bcast | R2Bcast | R2P2p { to: _ } | R3Bcast)) // don't match fail types
        .map(|msg_type| Stall { msg_type })
        .collect::<Vec<Behaviour>>();

    stallers
        .iter()
        .map(|staller| StallTestCase {
            threshold: 1,
            parties: vec![
                StallTestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                StallTestCaseParty {
                    behaviour: staller.clone(),
                    expected_crimes: vec![map_staller_to_crime(&staller)],
                },
                StallTestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        })
        .collect()
}
