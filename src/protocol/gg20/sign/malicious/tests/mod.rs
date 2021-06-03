use super::*;
use crate::protocol::{
    gg20::{
        keygen::tests_k256::execute_keygen,
        sign::{MsgMeta, MsgType},
        tests::sign::MSG_TO_SIGN,
    },
    tests::{execute_protocol_vec_with_criminals, Criminal},
    Protocol,
};
use tracing_test::traced_test; // enable logs in tests

struct SignSpoofer {
    index: usize,
    victim: usize,
    status: Status,
}

impl Criminal for SignSpoofer {
    fn index(&self) -> usize {
        self.index
    }
    // send to the victim the original message and a spoofed duplicated one
    fn do_crime(&self, original_msg: &[u8], victim: &mut dyn Protocol) {
        // first, send the message to receiver and then create a _duplicate_ message
        victim
            .set_msg_in(
                &original_msg,
                &IndexRange {
                    first: self.index,
                    last: self.index,
                },
            )
            .unwrap();

        // deserialize message and change `from` field
        let mut msg: MsgMeta = bincode::deserialize(original_msg).unwrap();
        msg.from = self.victim;
        let msg = bincode::serialize(&msg).unwrap();
        // send spoofed message to victim
        victim
            .set_msg_in(
                &msg,
                &IndexRange {
                    first: self.index,
                    last: self.index,
                },
            )
            .unwrap();
    }
    // check if the current round is the spoof round
    fn is_crime_round(&self, sender_idx: usize, msg: &[u8]) -> bool {
        if sender_idx != self.index {
            return false;
        }
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

struct SignStaller {
    index: usize,
    msg_type: MsgType,
}

impl Criminal for SignStaller {
    fn index(&self) -> usize {
        self.index
    }
    // don't send message to receiver
    fn do_crime(&self, _bytes: &[u8], _receiver: &mut dyn Protocol) {
        // hard is the life of a staller
    }
    // check if the current message is the one we want to stall
    fn is_crime_round(&self, sender_idx: usize, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        sender_idx == self.index && msg.msg_type == self.msg_type
    }
}

struct SignDisrupter {
    index: usize,
    msg_type: MsgType,
}

impl Criminal for SignDisrupter {
    fn index(&self) -> usize {
        self.index
    }
    // mess bytes and send to receiver
    fn do_crime(&self, original_msg: &[u8], receiver: &mut dyn Protocol) {
        // first, send the message to receiver and then create a _duplicate_ message
        receiver
            .set_msg_in(
                &original_msg,
                &IndexRange {
                    first: self.index,
                    last: self.index,
                },
            )
            .unwrap();

        // disrupt the message
        let disrupted_msg = original_msg.clone()[0..original_msg.len() / 2].to_vec();

        // send spoofed message to victim and ignore the result
        receiver
            .set_msg_in(
                &disrupted_msg,
                &IndexRange {
                    first: self.index,
                    last: self.index,
                },
            )
            .unwrap();
    }
    // check if the current message is the one we want to disrupt
    fn is_crime_round(&self, sender_idx: usize, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        sender_idx == self.index && msg.msg_type == self.msg_type
    }
}

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
    static ref SPOOF_BEFORE_CASES: Vec<TestCase> = generate_spoof_before_honest_cases();
    static ref SPOOF_AFTER_CASES: Vec<TestCase> = generate_spoof_after_honest_cases();
    static ref STALL_CASES: Vec<TestCase> = generate_stall_cases();
    static ref DISRUPT_CASES: Vec<TestCase> = generate_disrupt_cases();
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
// we detect whether a message is spoofed the moment we receive it so we should be
// able to find is successfully either receiving it before or after the original msg
fn spoof_messages() {
    execute_test_case_list(&SPOOF_BEFORE_CASES);
    execute_test_case_list(&SPOOF_AFTER_CASES);
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

#[test]
fn test_stall_cases() {
    execute_test_case_list(&STALL_CASES);
}

#[test]
fn test_disrupt_cases() {
    execute_test_case_list(&DISRUPT_CASES);
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
                &key_shares[p.party_index].group,
                &key_shares[p.party_index].share,
                &participant_indices,
                &MSG_TO_SIGN,
                p.behaviour.clone(),
            )
            .unwrap()
        })
        .collect();

    let spoofers: Vec<SignSpoofer> = signers
        .iter()
        .enumerate()
        .map(|(index, s)| match s.malicious_type.clone() {
            UnauthenticatedSender { victim, status: s } => Some(SignSpoofer {
                index,
                victim,
                status: s.clone(),
            }),
            _ => None,
        })
        .filter(|spoofer| spoofer.is_some())
        .map(|spoofer| spoofer.unwrap())
        .collect();

    let stallers: Vec<SignStaller> = signers
        .iter()
        .enumerate()
        .map(|(index, s)| match s.malicious_type.clone() {
            Staller { msg_type } => Some(SignStaller {
                index,
                msg_type: msg_type.clone(),
            }),
            _ => None,
        })
        .filter(|staller| staller.is_some())
        .map(|staller| staller.unwrap())
        .collect();

    let disrupters: Vec<SignDisrupter> = signers
        .iter()
        .enumerate()
        .map(|(index, s)| match s.malicious_type.clone() {
            DisrupringSender { msg_type } => Some(SignDisrupter {
                index,
                msg_type: msg_type.clone(),
            }),
            _ => None,
        })
        .filter(|disrupter| disrupter.is_some())
        .map(|disrupter| disrupter.unwrap())
        .collect();

    // need to do an extra iteration because we can't return reference to temp objects
    let mut criminals: Vec<&dyn Criminal> = spoofers.iter().map(|s| s as &dyn Criminal).collect();
    criminals.extend(stallers.iter().map(|s| s as &dyn Criminal));
    criminals.extend(disrupters.iter().map(|s| s as &dyn Criminal));

    let mut protocols: Vec<&mut dyn Protocol> =
        signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

    execute_protocol_vec_with_criminals(&mut protocols, &criminals);

    // TEST: honest parties finished and correctly computed the criminals list
    for signer in signers
        .iter()
        .filter(|s| matches!(s.malicious_type, Honest))
    {
        // if party has finished, check that result was the expected one
        if let Some(output) = signer.clone_output() {
            t.assert_expected_output(&output);
        }
        // else check for stalling parties
        else {
            let output = signer.waiting_on();
            t.assert_expected_waiting_on(&output);
        }
    }
}
