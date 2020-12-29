use std::collections::HashMap;
use bincode;

mod stateless;

use crate::protocol::{Protocol, State};
use stateless::*;

// pub fn new<ID>(party_ids: Vec<ID>, my_party_id: usize, threshold: usize) -> Protocol {
pub fn new(party_ids: &Vec<String>, my_party_id_index: usize, threshold: usize) -> Protocol {

    // prepare a map of expected incoming messages from other parties
    // each message is `None` until we receive it later
    let incoming_msgs = party_ids.iter().enumerate()
        .filter(|(index,_)| *index != my_party_id_index) // don't include myself
        .map(|(_,id)| (id.clone(), None)) // initialize to None
        .collect();

    let (state, output) = r1::start();
    Protocol {
        state: Some(Box::new(R1::<String>{
            state,
            output,
            incoming_msgs,
            threshold,
            my_uid: party_ids[my_party_id_index].clone(),
            num_incoming_msgs: 0,
        }))
    }
}

#[derive(Debug)]
pub struct R1<ID> {
    state: R1State,
    output: R1Bcast,
    incoming_msgs: HashMap<ID, Option<R1Bcast>>,
    threshold: usize,
    my_uid: ID,
    num_incoming_msgs: usize,
}

// impl<ID> State for R1<ID> {
impl State for R1<String> {

    fn add_message_in(&mut self, from: &str, msg: &Vec<u8>) {
        let stored = self.incoming_msgs.get_mut(from).unwrap(); // panic: unexpected party id
        if stored.is_some() {
            panic!("repeated message from party id {}", from);
        }
        let msg: R1Bcast = bincode::deserialize(msg).unwrap(); // panic: deserialization failure
        *stored = Some(msg);
        self.num_incoming_msgs += 1;
        assert!(self.num_incoming_msgs <= self.incoming_msgs.len());
    }

    fn can_proceed(&self) -> bool {self.num_incoming_msgs >= self.incoming_msgs.len()}

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output).unwrap(); // panic: serialization failure
        (
            Some(bcast),
            HashMap::new() // no p2p msgs this round
        )
    }

    fn next(self: Box<Self>) -> Box<dyn State> {
        assert!(self.can_proceed());
        let incoming_bcast = self.incoming_msgs.keys().cloned().map(|k| (k,None)).collect();
        let incoming_p2p = self.incoming_msgs.keys().cloned().map(|k| (k,None)).collect();
        let inputs = R2Input{
            other_r1_bcasts: self.incoming_msgs.into_iter().map(|(k,v)| (k, v.unwrap())).collect(),
            threshold: self.threshold,
            my_uid: self.my_uid,
        };
        let (state, output) = r2::execute(self.state, inputs);
        Box::new(R2{
            state,
            output_bcast: output.broadcast,
            output_p2p: output.p2p,
            incoming_bcast,
            num_incoming_bcast: 0,
            incoming_p2p,
            num_incoming_p2p: 0,
        })
    }
}

#[derive(Debug)]
// pub struct R2<ID> {foo: ID}
pub struct R2<ID> {
    state: R2State<ID>,
    output_bcast: R2Bcast,
    output_p2p: HashMap<ID, R2P2p>, // TODO use &ID instead of ID?
    incoming_bcast: HashMap<ID, Option<R2Bcast>>, // TODO use &ID instead of ID?
    num_incoming_bcast: usize, // TODO refactor incoming, num_incoming into a separate data structure
    incoming_p2p: HashMap<ID, Option<R2P2p>>,
    num_incoming_p2p: usize,
}

// impl<ID> State for R2<ID> {
impl State for R2<String> {

    fn add_message_in(&mut self, from: &str, msg: &Vec<u8>) {
        // msg can be either R2Bcast or R2P2p
        // TODO lots of refactoring needed
        if let Ok(bcast) = bincode::deserialize(msg) {
            let stored = self.incoming_bcast.get_mut(from).unwrap(); // panic: unexpected party id
            if stored.is_some() {
                panic!("repeated bcast message from party id {}", from);
            }
            *stored = Some(bcast);
            self.num_incoming_bcast += 1;
            assert!(self.num_incoming_bcast <= self.incoming_bcast.len());
            return;
        }
        if let Ok(p2p) = bincode::deserialize(msg) {
            let stored = self.incoming_p2p.get_mut(from).unwrap(); // panic: unexpected party id
            if stored.is_some() {
                panic!("repeated p2p message from party id {}", from);
            }
            *stored = Some(p2p);
            self.num_incoming_p2p += 1;
            assert!(self.num_incoming_p2p <= self.incoming_p2p.len());
            return;
        }
        panic!("deserialization failure");
    }

    fn can_proceed(&self) -> bool {
        (self.num_incoming_bcast >= self.incoming_bcast.len())
        &&
        (self.num_incoming_p2p >= self.incoming_p2p.len())
    }

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output_bcast).unwrap(); // panic: serialization failure
        let p2p = self.output_p2p.iter().map(|(k,v)|
            (
                k.clone(), // TODO use &ID instead of ID?
                bincode::serialize(v).unwrap() // panic: serialization failure
            )).collect();
        (
            Some(bcast),
            p2p,
        )
    }

    fn next(self: Box<Self>) -> Box<dyn State> {
        assert!(self.can_proceed());
        Box::new(R3{})
    }
}

#[derive(Debug)]
pub struct R3{}

// dummy impl State
impl State for R3 {
    fn add_message_in(&mut self, _from: &str, _msg: &Vec<u8>) {}
    fn can_proceed(&self) -> bool {false}
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {(None, HashMap::new())}
    fn next(self: Box<Self>) -> Box<dyn State> {self}
}
