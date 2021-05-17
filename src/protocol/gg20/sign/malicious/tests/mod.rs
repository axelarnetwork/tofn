use super::*;
use crate::protocol::{
    gg20::{
        keygen::tests::execute_keygen,
        sign::{MsgMeta, MsgType},
    },
    tests::{execute_protocol_vec_spoof, Spoofer},
    Protocol,
};
use tracing_test::traced_test; // enable logs in tests

static MESSAGE_TO_SIGN: [u8; 2] = [42, 24];

struct SignSpoofer {
    index: usize,
    victim: usize,
    status: Status,
}

impl Spoofer for SignSpoofer {
    fn index(&self) -> usize {
        self.index
    }
    fn spoof(&self, original_msg: &[u8]) -> Vec<u8> {
        let mut msg: MsgMeta = bincode::deserialize(original_msg).unwrap();
        msg.from = self.victim;
        bincode::serialize(&msg).unwrap()
    }
    fn is_spoof_round(&self, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        let msg_type = match msg.msg_type {
            MsgType::R1Bcast => Status::R1,
            MsgType::R1P2p { to: _ } => Status::R1,
            MsgType::R2P2p { to: _ } => Status::R2,
            MsgType::R2FailBcast => Status::R2,
            MsgType::R3Bcast => Status::R3,
            MsgType::R3FailBcast => Status::R3,
            MsgType::R4Bcast => Status::R4,
            MsgType::R5Bcast => Status::R5,
            MsgType::R5P2p { to: _ } => Status::R5,
            MsgType::R6Bcast => Status::R6,
            MsgType::R6FailBcast => Status::R6,
            MsgType::R6FailType5Bcast => Status::R6,
            MsgType::R7Bcast => Status::R7,
            MsgType::R7FailType7Bcast => Status::R7,
        };
        msg_type == self.status
    }
}

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
    static ref SUCCESS_SPOOF_CASES: Vec<TestCase> = generate_success_unauth_cases();
    static ref FAILED_SPOOF_CASES: Vec<TestCase> = generate_failed_unauth_cases();
    static ref SKIPPING_CASES: Vec<TestCase> = generate_skipping_cases();
    static ref SAME_ROUND_CASES: Vec<TestCase> = generate_multiple_faults_in_same_round();
    static ref MULTIPLE_VICTIMS: Vec<TestCase> = generate_target_multiple_parties();
    static ref MULTIPLE_FAULTS: Vec<TestCase> = generate_multiple_faults();
    static ref PANIC_THRESHOLD: Vec<TestCase> = generate_small_threshold();
    static ref PANIC_INDEX: Vec<TestCase> = generate_out_of_index();
}

#[test]
#[traced_test]
fn basic_tests() {
    execute_test_case_list(&BASIC_CASES);
}

#[test]
#[traced_test]
fn spoof_tests() {
    execute_test_case_list(&SUCCESS_SPOOF_CASES);
    execute_test_case_list(&FAILED_SPOOF_CASES);
}

#[test]
#[traced_test]
fn skipping_cases() {
    execute_test_case_list(&SKIPPING_CASES);
}

#[test]
#[traced_test]
fn same_round_cases() {
    execute_test_case_list(&SAME_ROUND_CASES);
}

#[test]
#[traced_test]
fn multiple_targets_cases() {
    execute_test_case_list(&MULTIPLE_VICTIMS);
}

#[test]
#[traced_test]
fn multiple_faults() {
    execute_test_case_list(&MULTIPLE_FAULTS);
}

#[test]
#[should_panic]
fn panic_small_threshold() {
    execute_test_case_list(&PANIC_THRESHOLD);
}

#[test]
#[should_panic]
fn panic_out_of_index() {
    execute_test_case_list(&PANIC_INDEX);
}

fn execute_test_case_list(test_cases: &[test_cases::TestCase]) {
    for t in test_cases {
        let malicious_participants: Vec<(usize, MaliciousType)> = t
            .sign_participants
            .iter()
            .enumerate()
            .filter(|p| !matches!(p.1.behaviour, Honest))
            .map(|p| (p.0, p.1.behaviour.clone()))
            .collect();
        info!(
            "share_count [{}] threshold [{}]",
            t.share_count, t.threshold
        );
        info!("malicious participants {:?}", malicious_participants);
        execute_test_case(t);
    }
}

fn execute_test_case(t: &test_cases::TestCase) {
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

    let spoofers: Vec<SignSpoofer> = signers
        .iter()
        .map(|s| match s.malicious_type.clone() {
            UnauthenticatedSender { victim, status: s } => Some(SignSpoofer {
                index: 0,
                victim,
                status: s.clone(),
            }),
            _ => None,
        })
        .filter(|spoofer| spoofer.is_some())
        .map(|spoofer| spoofer.unwrap())
        .collect();

    // need to do an extra iteration because we can't return reference to temp objects
    let spoofers: Vec<&dyn Spoofer> = spoofers.iter().map(|s| s as &dyn Spoofer).collect();

    let mut protocols: Vec<&mut dyn Protocol> =
        signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

    execute_protocol_vec_spoof(&mut protocols, &spoofers);

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
