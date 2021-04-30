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
        // r3_fail
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
        // r8_fail_randomizer
        TestCase {
            share_count: 5,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 4,
                    behaviour: R3BadNonceXBlindSummand,
                    expected_crimes: vec![Crime::R8BadNonceXBlindSummand],
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: R3BadNonceXBlindSummand,
                    expected_crimes: vec![Crime::R8BadNonceXBlindSummand],
                },
            ],
        },
        // r8_fail_randomizer
        TestCase {
            share_count: 5,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 0,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 4,
                    behaviour: R3BadEcdsaNonceSummand,
                    expected_crimes: vec![Crime::R8BadNonceSummand],
                },
            ],
        },
        // r8_fail_randomizer
        TestCase {
            share_count: 5,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 1,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 0,
                    behaviour: R1BadSecretBlindSummand,
                    expected_crimes: vec![Crime::R8BadBlindSummand],
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        },
        // r8_fail_randomizer
        TestCase {
            share_count: 4,
            threshold: 3,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 1,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 0,
                    behaviour: R3BadMtaBlindSummandRhs { victim: 3 },
                    expected_crimes: vec![Crime::R8MtaBlindSummandRhs { victim: 3 }],
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        },
        // r8_fail_randomizer
        TestCase {
            share_count: 4,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 0,
                    behaviour: R3BadMtaBlindSummandLhs { victim: 2 },
                    expected_crimes: vec![Crime::R8MtaBlindSummandLhs { victim: 2 }],
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
            ],
        },
        // r8_fail_randomizer
        TestCase {
            share_count: 4,
            threshold: 2,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 3,
                    behaviour: Honest,
                    expected_crimes: vec![],
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: R6FalseFailRandomizer,
                    expected_crimes: vec![Crime::R8FalseComplaint],
                },
                SignParticipant {
                    party_index: 1,
                    behaviour: R6FalseFailRandomizer,
                    expected_crimes: vec![Crime::R8FalseComplaint],
                },
            ],
        },
    ]
}
