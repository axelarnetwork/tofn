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

// #[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_some_test_cases() -> Vec<TestCase> {
    vec![
        // multiple faults in round 1
        TestCase {
            share_count: 5,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 4,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: R1BadProof { victim: 0 },
                    expected_crimes: vec![Crime::R3BadRangeProof { victim: 0 }],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        },
    ]
}
