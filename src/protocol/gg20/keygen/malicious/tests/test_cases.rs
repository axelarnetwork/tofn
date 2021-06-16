use strum::IntoEnumIterator;

use super::{Behaviour, Behaviour::*};
use crate::protocol::gg20::keygen::{crimes::Crime, KeygenOutput, MsgType, Status};

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
                println!("Crimes found: {:?}", criminals);
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
    pub(crate) fn assert_expected_waiting_on(&self, output: &[Vec<Crime>]) {
        let mut expected_output = vec![];
        for p in &self.parties {
            expected_output.push(p.expected_crimes.clone());
        }
        assert_eq!(output, expected_output);
    }
    pub(super) fn share_count(&self) -> usize {
        self.parties.len()
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
        matches!(self, Staller { msg_type: _ })
    }

    pub(super) fn is_disrupter(&self) -> bool {
        matches!(self, DisruptingSender { msg_type: _ })
    }

    /// Return the `Crime` variant `c` such that
    /// if one party acts according to `self` and all other parties are honest
    /// then honest parties will detect `c`.
    /// Panics if `self` is `Honest`
    pub(super) fn to_crime(&self) -> Crime {
        match self {
            Honest => panic!("`to_crime` called with `Honest`"),
            Staller { msg_type: mt } => Crime::StalledMessage {
                msg_type: mt.clone(),
            },
            UnauthenticatedSender {
                victim: v,
                status: s,
            } => Crime::SpoofedMessage {
                victim: *v,
                status: s.clone(),
            },
            DisruptingSender { msg_type: _ } => Crime::DisruptedMessage,
            R1BadEncryptionKeyProof => Crime::R2BadEncryptionKeyProof,
            R1BadZkSetupProof => Crime::R2BadZkSetupProof,
            R1BadCommit => Crime::R3BadReveal,
            R2BadShare { victim: v } => Crime::R4FailBadVss { victim: *v },
            R2BadEncryption { victim: v } => Crime::R4FailBadEncryption { victim: *v },
            R3FalseAccusation { victim: v } => Crime::R4FailFalseAccusation { victim: *v },
            R3BadXIWitness => Crime::R4BadDLProof,
        }
    }
}

// Test all basic cases with one malicious behaviour per test case
// #[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_basic_cases() -> Vec<TestCase> {
    Behaviour::iter()
        .filter(|b| {
            !b.is_honest() && !b.is_spoofer() && !b.is_staller() && !b.is_disrupter()
            // && matches!(b, R2BadShare { victim: _ })
        })
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

// create stallers
pub(super) fn generate_stall_cases() -> Vec<TestCase> {
    use MsgType::*;
    let stallers = MsgType::iter()
        .filter(|msg_type| matches!(msg_type, R1Bcast | R2Bcast | R2P2p { to: _ } | R3Bcast)) // don't match fail types
        .map(|msg_type| Staller { msg_type })
        .collect::<Vec<Behaviour>>();

    stallers
        .iter()
        .map(|staller| TestCase {
            threshold: 1,
            expect_success: false,
            parties: vec![
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                TestCaseParty {
                    behaviour: staller.clone(),
                    expected_crimes: vec![staller.to_crime()],
                },
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        })
        .collect()
}

pub(super) fn generate_disrupted_cases() -> Vec<TestCase> {
    use MsgType::*;
    let criminals = MsgType::iter()
        .filter(|msg_type| matches!(msg_type, R1Bcast | R2Bcast | R2P2p { to: _ } | R3Bcast)) // don't match fail types
        .map(|msg_type| DisruptingSender { msg_type })
        .collect::<Vec<Behaviour>>();

    criminals
        .iter()
        .map(|criminal| TestCase {
            threshold: 1,
            expect_success: false,
            parties: vec![
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                TestCaseParty {
                    behaviour: criminal.clone(),
                    expected_crimes: vec![criminal.to_crime()],
                },
                TestCaseParty {
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        })
        .collect()
}
