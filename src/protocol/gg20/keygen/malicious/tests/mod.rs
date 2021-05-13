// TODO refactor copied code from sign protocol
use super::Behaviour;
use crate::protocol::{
    gg20::keygen::{Keygen, MsgMeta, MsgType, Status},
    tests::{execute_protocol_vec_spoof, Spoofer},
    Protocol,
};
use tracing::info;
use tracing_test::traced_test; // enable logs in tests

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
    static ref SELF_ACCUSATION: Vec<TestCase> = self_accusation_cases();
    static ref SUCCESS_SPOOF_CASES: Vec<TestCase> = generate_success_spoof_cases();
    static ref FAILED_SPOOF_CASES: Vec<TestCase> = generate_failed_spoof_cases();
}

struct KeygenSpoofer {
    index: usize,
    victim: usize,
    status: Status,
}

impl Spoofer for KeygenSpoofer {
    fn index(&self) -> usize {
        self.index
    }
    fn spoof(&self, original_msg: &[u8]) -> Vec<u8> {
        let mut msg: MsgMeta = bincode::deserialize(original_msg).unwrap();
        msg.from = self.victim;
        bincode::serialize(&msg).unwrap()
    }
    // map message types to the round they are created
    fn is_spoof_round(&self, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        let curr_status = match msg.msg_type {
            MsgType::R1Bcast => Status::New,
            MsgType::R2Bcast => Status::R1,
            MsgType::R2P2p { to: _ } => Status::R1,
            MsgType::R3Bcast => Status::R2,
            MsgType::R3FailBcast => Status::R2,
        };
        curr_status == self.status // why can't I use matches?
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
fn spoof_messages() {
    execute_test_case_list(&SUCCESS_SPOOF_CASES);
    execute_test_case_list(&FAILED_SPOOF_CASES);
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
            let mut k = Keygen::new(t.share_count(), t.threshold, i).unwrap();
            k.behaviour = p.behaviour.clone();
            k
        })
        .collect();

    let spoofers: Vec<KeygenSpoofer> = keygen_parties
        .iter_mut()
        .map(|s| match s.behaviour.clone() {
            Behaviour::UnauthenticatedSender { victim, status: s } => Some(KeygenSpoofer {
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

    let mut protocols: Vec<&mut dyn Protocol> = keygen_parties
        .iter_mut()
        .map(|p| p as &mut dyn Protocol)
        .collect();

    execute_protocol_vec_spoof(&mut protocols, t.allow_self_delivery, &spoofers);

    // TEST: honest parties finished and correctly computed the criminals list
    for keygen_party in keygen_parties.iter().filter(|k| k.behaviour.is_honest()) {
        let output = keygen_party
            .clone_output()
            .unwrap_or_else(|| panic!("honest party {} did not finish", keygen_party.my_index,));
        t.assert_expected_output(&output);
    }
}
