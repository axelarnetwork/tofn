//! Stateful keygen happy path
//! TODO It's confusing to have R1,... structs that hold R1State,... data
use std::collections::HashMap;

mod stateless;

use crate::{
    fillmap::FillMap,
    protocol::{Protocol, State},
};
use stateless::*;

pub fn new_protocol(ids: &[String], my_id_index: usize, threshold: usize) -> Protocol<FinalOutput> {
    let (my_state, my_output) = r1::start();

    // prepare a FillMap for expected incoming messages from other parties
    let incoming_bcasts = ids
        .iter()
        .enumerate() // s -> (i,s)
        .filter(|(i, _)| *i != my_id_index) // don't include myself
        .map(|(_, s)| s) // (i,s) -> s
        .cloned()
        .collect();
    Protocol {
        state: Some(Box::new(R1 {
            my_state,
            my_output,
            my_id: ids[my_id_index].clone(),
            threshold,
            incoming_bcasts,
        })),
    }
}

#[derive(Debug)]
pub struct R1 {
    my_state: R1State,
    my_output: R1Bcast,
    my_id: String,
    threshold: usize,
    incoming_bcasts: FillMap<String, R1Bcast>,
}

impl State for R1 {
    type Result = FinalOutput;

    fn add_message_in(&mut self, from: &str, msg: &[u8]) {
        let msg: R1Bcast = bincode::deserialize(msg).unwrap(); // panic: deserialization failure
        self.incoming_bcasts.insert(from.to_string(), msg).unwrap(); // panic: FillMap error
    }

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        let bcast = bincode::serialize(&self.my_output).unwrap(); // panic: serialization failure
        (
            Some(bcast),
            HashMap::new(), // no p2p msgs this round
        )
    }

    fn next(self: Box<Self>) -> Box<dyn State<Result = Self::Result> + Send> {
        assert!(self.can_proceed());
        let other_r1_bcasts = self.incoming_bcasts.into_hashmap();
        let incoming_bcast = other_r1_bcasts.keys().cloned().map(|k| (k, None)).collect();
        let incoming_p2p = other_r1_bcasts.keys().cloned().map(|k| (k, None)).collect();
        let inputs = R2Input {
            other_r1_bcasts,
            threshold: self.threshold,
            my_uid: self.my_id.clone(),
        };
        let (state, output) = r2::execute(self.my_state, inputs);
        Box::new(R2 {
            my_id: self.my_id,
            state,
            output_bcast: output.bcast,
            output_p2p: output.p2p,
            incoming_bcast,
            num_incoming_bcast: 0,
            incoming_p2p,
            num_incoming_p2p: 0,
        })
    }

    fn can_proceed(&self) -> bool {
        self.incoming_bcasts.is_full()
    }
    fn get_id(&self) -> &str {
        &self.my_id
    }
    fn done(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct R2 {
    my_id: String,
    state: R2State,
    output_bcast: R2Bcast,
    output_p2p: HashMap<String, R2P2p>, // TODO use &ID instead of ID?
    incoming_bcast: HashMap<String, Option<R2Bcast>>, // TODO use &ID instead of ID?
    num_incoming_bcast: usize, // TODO refactor incoming, num_incoming into a separate data structure
    incoming_p2p: HashMap<String, Option<R2P2p>>,
    num_incoming_p2p: usize,
}

impl State for R2 {
    type Result = FinalOutput;
    fn add_message_in(&mut self, from: &str, msg: &[u8]) {
        // msg can be either R2Bcast or R2P2p
        // TODO lots of refactoring needed
        if let Ok(bcast) = bincode::deserialize(msg) {
            let stored = self.incoming_bcast.get_mut(from).unwrap(); // panic: unexpected party id
            if stored.is_some() {
                panic!("repeated bcast message from party id {:?}", from);
            }
            *stored = Some(bcast);
            self.num_incoming_bcast += 1;
            assert!(self.num_incoming_bcast <= self.incoming_bcast.len());
            return;
        }
        if let Ok(p2p) = bincode::deserialize(msg) {
            let stored = self.incoming_p2p.get_mut(from).unwrap(); // panic: unexpected party id
            if stored.is_some() {
                panic!("repeated p2p message from party id {:?}", from);
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
            && (self.num_incoming_p2p >= self.incoming_p2p.len())
    }

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output_bcast).unwrap(); // panic: serialization failure
        let p2p = self
            .output_p2p
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),                      // TODO use &ID instead of ID?
                    bincode::serialize(v).unwrap(), // panic: serialization failure
                )
            })
            .collect();
        (Some(bcast), p2p)
    }

    fn next(self: Box<Self>) -> Box<dyn State<Result = Self::Result> + Send> {
        assert!(self.can_proceed());
        let incoming = self
            .incoming_bcast
            .keys()
            .cloned()
            .map(|k| (k, None))
            .collect();
        let inputs = R3Input {
            other_r2_msgs: self
                .incoming_bcast
                .iter()
                .map(|(k, v)| {
                    // TODO lots of cloning here
                    let p2p = self.incoming_p2p.get(k).unwrap().clone().unwrap();
                    (k.clone(), (v.clone().unwrap(), p2p))
                })
                .collect(),
        };
        let (state, output) = r3::execute(self.state, inputs);
        Box::new(R3 {
            my_id: self.my_id,
            state,
            output,
            incoming,
            num_incoming: 0,
        })
    }

    fn get_id(&self) -> &str {
        &self.my_id
    }
    fn done(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct R3 {
    my_id: String,
    state: R3State,
    output: R3Bcast,
    incoming: HashMap<String, Option<R3Bcast>>,
    num_incoming: usize,
}

// TODO refactor repeated code from R1, R2
impl State for R3 {
    type Result = FinalOutput;

    fn add_message_in(&mut self, from: &str, msg: &[u8]) {
        let stored = self.incoming.get_mut(from).unwrap(); // panic: unexpected party id
        if stored.is_some() {
            panic!("repeated message from party id {:?}", from);
        }
        let msg: R3Bcast = bincode::deserialize(msg).unwrap(); // panic: deserialization failure
        *stored = Some(msg);
        self.num_incoming += 1;
        assert!(self.num_incoming <= self.incoming.len());
    }

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output).unwrap(); // panic: serialization failure
        (
            Some(bcast),
            HashMap::new(), // no p2p msgs this round
        )
    }

    fn next(self: Box<Self>) -> Box<dyn State<Result = Self::Result> + Send> {
        assert!(self.can_proceed());
        let inputs = R4Input {
            other_r3_bcasts: self
                .incoming
                .into_iter()
                .map(|(k, v)| (k, v.unwrap()))
                .collect(),
        };
        let state = r4::execute(self.state, inputs);
        Box::new(R4 {
            my_id: self.my_id,
            state,
        })
    }

    fn can_proceed(&self) -> bool {
        self.num_incoming >= self.incoming.len()
    }
    fn get_id(&self) -> &str {
        &self.my_id
    }
    fn done(&self) -> bool {
        false
    }
}

pub struct R4 {
    my_id: String,
    state: FinalOutput,
}
impl State for R4 {
    type Result = FinalOutput;
    fn add_message_in(&mut self, _from: &str, _msg: &[u8]) {}
    fn can_proceed(&self) -> bool {
        false
    }
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        (None, HashMap::new())
    }
    fn get_id(&self) -> &str {
        &self.my_id
    }
    fn next(self: Box<Self>) -> Box<dyn State<Result = Self::Result> + Send> {
        self
    }
    fn done(&self) -> bool {
        true
    }
    fn get_result(&self) -> Option<Self::Result> {
        Some(self.state.clone())
    }
}

#[cfg(test)]
mod tests;
