// TODO refactor copied code from sign protocol
use super::Behaviour;
use crate::protocol::{
    gg20::keygen::{Keygen, MsgMeta, MsgType, Status},
    tests::{execute_protocol_vec_with_criminals, Criminal},
    IndexRange, Protocol,
};
use rand::RngCore;
use tracing::info;
use tracing_test::traced_test; // enable logs in tests

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
    static ref SELF_ACCUSATION: Vec<TestCase> = self_accusation_cases();
    static ref SPOOF_BEFORE_CASES: Vec<TestCase> = generate_spoof_before_honest_cases();
    static ref SPOOF_AFTER_CASES: Vec<TestCase> = generate_spoof_after_honest_cases();
    static ref STALL_CASES: Vec<TestCase> = generate_stall_cases();
    static ref DISRUPTED_CASES: Vec<TestCase> = generate_disrupted_cases();
}

struct KeygenSpoofer {
    index: usize,
    victim: usize,
    status: Status,
}

impl Criminal for KeygenSpoofer {
    fn index(&self) -> usize {
        self.index
    }
    // send to the victim the original message and a spoofed duplicated one
    fn do_crime(&self, original_msg: &[u8], victim: &mut dyn Protocol) {
        // first, send the message to receiver and then create a _duplicate_ message
        victim.set_msg_in(
            &original_msg,
            &IndexRange {
                first: self.index,
                last: self.index,
            },
        );

        // deserialize message and change `from` field
        let mut msg: MsgMeta = bincode::deserialize(original_msg).unwrap();
        msg.from = self.victim;
        let msg = bincode::serialize(&msg).unwrap();
        // send spoofed message to victim
        victim.set_msg_in(
            &msg,
            &IndexRange {
                first: self.index,
                last: self.index,
            },
        );
    }
    // check if the current round is the spoof round
    fn is_crime_round(&self, sender_idx: usize, msg: &[u8]) -> bool {
        if sender_idx != self.index {
            return false;
        }
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        let curr_status = match msg.msg_type {
            MsgType::R1Bcast => Status::R1,
            MsgType::R2Bcast => Status::R2,
            MsgType::R2P2p { to: _ } => Status::R2,
            MsgType::R3Bcast => Status::R3,
            MsgType::R3FailBcast => Status::R3,
        };
        curr_status == self.status // why can't I use matches?
    }
}
struct KeygenStaller {
    index: usize,
    msg_type: MsgType,
}

impl Criminal for KeygenStaller {
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

struct KeygenDisrupter {
    index: usize,
    msg_type: MsgType,
}

impl Criminal for KeygenDisrupter {
    fn index(&self) -> usize {
        self.index
    }
    // mess bytes and send to receiver
    fn do_crime(&self, original_msg: &[u8], receiver: &mut dyn Protocol) {
        // first, send the message to receiver and then create a _duplicate_ message
        receiver.set_msg_in(
            &original_msg,
            &IndexRange {
                first: self.index,
                last: self.index,
            },
        );

        // disrupt the message
        let disrupted_msg = original_msg[0..original_msg.len() / 2].to_vec();

        // send spoofed message to victim and ignore the result
        receiver.set_msg_in(
            &disrupted_msg,
            &IndexRange {
                first: self.index,
                last: self.index,
            },
        );
    }
    // check if the current message is the one we want to disrupt
    fn is_crime_round(&self, sender_idx: usize, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        sender_idx == self.index && msg.msg_type == self.msg_type
    }
}

#[test]
#[traced_test]
fn basic_tests() {
    execute_test_case_list(&BASIC_CASES);
}

#[test]
#[traced_test]
fn self_accusation() {
    execute_test_case_list(&SELF_ACCUSATION);
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
fn test_stall_cases() {
    execute_test_case_list(&STALL_CASES);
}

#[test]
fn test_disrupted_cases() {
    execute_test_case_list(&DISRUPTED_CASES);
}

fn execute_test_case_list(test_cases: &[test_cases::TestCase]) {
    for t in test_cases {
        info!(
            "share_count [{}] threshold [{}]",
            t.share_count(),
            t.threshold
        );
        let malicious_parties: Vec<(usize, Behaviour)> = t
            .parties
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.behaviour.is_honest())
            .map(|(i, p)| (i, p.behaviour.clone()))
            .collect();
        info!("malicious participants {:?}", malicious_parties);
        execute_test_case(t);
    }
}

fn execute_test_case(t: &test_cases::TestCase) {
    let mut keygen_parties: Vec<Keygen> = t
        .parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut prf_secret_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut prf_secret_key);

            let mut k = Keygen::new(
                t.share_count(),
                t.threshold,
                i,
                &prf_secret_key,
                &i.to_be_bytes(),
            )
            .unwrap();
            k.behaviour = p.behaviour.clone();
            k
        })
        .collect();

    let spoofers: Vec<KeygenSpoofer> = keygen_parties
        .iter_mut()
        .enumerate()
        .map(|(index, s)| match s.behaviour.clone() {
            Behaviour::UnauthenticatedSender { victim, status: s } => Some(KeygenSpoofer {
                index,
                victim,
                status: s,
            }),
            _ => None,
        })
        .filter(|spoofer| spoofer.is_some())
        .map(|spoofer| spoofer.unwrap())
        .collect();

    let stallers: Vec<KeygenStaller> = keygen_parties
        .iter_mut()
        .enumerate()
        .map(|(index, s)| match s.behaviour.clone() {
            Behaviour::Staller { msg_type } => Some(KeygenStaller { index, msg_type }),
            _ => None,
        })
        .filter(|staller| staller.is_some())
        .map(|staller| staller.unwrap())
        .collect();

    let disrupters: Vec<KeygenDisrupter> = keygen_parties
        .iter_mut()
        .enumerate()
        .map(|(index, s)| match s.behaviour.clone() {
            Behaviour::DisruptingSender { msg_type } => Some(KeygenDisrupter { index, msg_type }),
            _ => None,
        })
        .filter(|disrupter| disrupter.is_some())
        .map(|disrupter| disrupter.unwrap())
        .collect();

    // need to do an extra iteration because we can't return reference to temp objects
    let mut criminals: Vec<&dyn Criminal> = spoofers.iter().map(|s| s as &dyn Criminal).collect();
    criminals.extend(stallers.iter().map(|s| s as &dyn Criminal));
    criminals.extend(disrupters.iter().map(|s| s as &dyn Criminal));

    let mut protocols: Vec<&mut dyn Protocol> = keygen_parties
        .iter_mut()
        .map(|p| p as &mut dyn Protocol)
        .collect();

    execute_protocol_vec_with_criminals(&mut protocols, &criminals);

    // TEST: honest parties finished and correctly computed the criminals list
    for keygen_party in keygen_parties.iter().filter(|k| k.behaviour.is_honest()) {
        // if party has finished, check that result was the expected one
        if let Some(output) = keygen_party.clone_output() {
            t.assert_expected_output(&output);
        } else {
            // check for stalling parties
            let output = keygen_party.waiting_on();
            t.assert_expected_waiting_on(&output);
        }
    }
}
