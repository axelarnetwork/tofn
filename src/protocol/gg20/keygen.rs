//! Stateful keygen happy path
use std::{
    collections::HashMap,
    hash::Hash,
    fmt::Debug,
};
use bincode;

mod stateless;

use crate::protocol::{Protocol, State};
use stateless::*;

pub fn new_protocol<'a, ID: 'static>(party_ids: &Vec<ID>, my_party_id_index: usize, threshold: usize) -> Protocol<ID>
    where ID: Eq + Hash + Ord + Clone + Debug
{
    // prepare a map of expected incoming messages from other parties
    // each message is `None` until we receive it later
    let incoming_msgs = party_ids.iter().enumerate()
        .filter(|(index,_)| *index != my_party_id_index) // don't include myself
        .map(|(_,id)| (id.clone(), None)) // initialize to None
        .collect();

    let (state, output) = r1::start();
    Protocol {
        state: Some(Box::new(R1::<ID>{
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

impl<ID: 'static> State<ID> for R1<ID>
    where ID: Eq + Hash + Ord + Clone + Debug
{
    fn add_message_in(&mut self, from: &ID, msg: &Vec<u8>) {
        let stored = self.incoming_msgs.get_mut(from).unwrap(); // panic: unexpected party id
        if stored.is_some() {
            panic!("repeated message from party id {:?}", from);
        }
        let msg: R1Bcast = bincode::deserialize(msg).unwrap(); // panic: deserialization failure
        *stored = Some(msg);
        self.num_incoming_msgs += 1;
        assert!(self.num_incoming_msgs <= self.incoming_msgs.len());
    }

    fn can_proceed(&self) -> bool {self.num_incoming_msgs >= self.incoming_msgs.len()}

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<ID, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output).unwrap(); // panic: serialization failure
        (
            Some(bcast),
            HashMap::new() // no p2p msgs this round
        )
    }

    fn get_id(&self) -> &ID {&self.my_uid}

    fn next(self: Box<Self>) -> Box<dyn State<ID>> {
        assert!(self.can_proceed());
        let incoming_bcast = self.incoming_msgs.keys().cloned().map(|k| (k,None)).collect();
        let incoming_p2p = self.incoming_msgs.keys().cloned().map(|k| (k,None)).collect();
        let inputs = R2Input{
            other_r1_bcasts: self.incoming_msgs.into_iter().map(|(k,v)| (k, v.unwrap())).collect(),
            threshold: self.threshold,
            my_uid: self.my_uid.clone(),
        };
        let (state, output) = r2::execute(self.state, inputs);
        Box::new(R2{
            my_id: self.my_uid,
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
pub struct R2<ID> {
    my_id: ID,
    state: R2State<ID>,
    output_bcast: R2Bcast,
    output_p2p: HashMap<ID, R2P2p>, // TODO use &ID instead of ID?
    incoming_bcast: HashMap<ID, Option<R2Bcast>>, // TODO use &ID instead of ID?
    num_incoming_bcast: usize, // TODO refactor incoming, num_incoming into a separate data structure
    incoming_p2p: HashMap<ID, Option<R2P2p>>,
    num_incoming_p2p: usize,
}

impl<ID: 'static> State<ID> for R2<ID>
    where ID: Eq + Hash + Ord + Clone + Debug
{
    fn add_message_in(&mut self, from: &ID, msg: &Vec<u8>) {
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
        &&
        (self.num_incoming_p2p >= self.incoming_p2p.len())
    }

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<ID, Vec<u8>>) {
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

    fn get_id(&self) -> &ID {&self.my_id}

    fn next(self: Box<Self>) -> Box<dyn State<ID>> {
        assert!(self.can_proceed());
        let incoming = self.incoming_bcast.keys().cloned().map(|k| (k,None)).collect();
        let inputs = R3Input{
            other_r2_msgs: self.incoming_bcast.iter().map(|(k,v)| {
                // TODO lots of cloning here
                let p2p = self.incoming_p2p.get(k).unwrap().clone().unwrap();
                (
                    k.clone(),
                    (v.clone().unwrap(), p2p)
                )
            }).collect(),
        };
        let (state, output) = r3::execute(self.state, inputs);
        Box::new(R3{
            my_id: self.my_id,
            state,
            output,
            incoming,
            num_incoming: 0,
        })
    }
}

#[derive(Debug)]
pub struct R3<ID> {
    my_id: ID,
    state: R3State,
    output: R3Bcast,
    incoming: HashMap<ID, Option<R3Bcast>>,
    num_incoming: usize,
}

// TODO refactor repeated code from R1, R2
impl<ID: 'static> State<ID> for R3<ID>
    where ID: Eq + Hash + Ord + Clone + Debug
{
    fn add_message_in(&mut self, from: &ID, msg: &Vec<u8>) {
        let stored = self.incoming.get_mut(from).unwrap(); // panic: unexpected party id
        if stored.is_some() {
            panic!("repeated message from party id {:?}", from);
        }
        let msg: R3Bcast = bincode::deserialize(msg).unwrap(); // panic: deserialization failure
        *stored = Some(msg);
        self.num_incoming += 1;
        assert!(self.num_incoming <= self.incoming.len());
    }

    fn can_proceed(&self) -> bool {self.num_incoming >= self.incoming.len()}

    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<ID, Vec<u8>>) {
        let bcast = bincode::serialize(&self.output).unwrap(); // panic: serialization failure
        (
            Some(bcast),
            HashMap::new() // no p2p msgs this round
        )
    }

    fn get_id(&self) -> &ID {&self.my_id}

    fn next(self: Box<Self>) -> Box<dyn State<ID>> {
        assert!(self.can_proceed());
        let inputs = R4Input{
            other_r3_bcasts: self.incoming.into_iter().map(|(k,v)| (k,v.unwrap()) ).collect(),
        };
        let state = r4::execute(self.state, inputs);
        Box::new(R4{
            my_id: self.my_id,
            state,
        })
    }
}

// TODO what to do with the result?
pub struct R4<ID>{
    my_id: ID,
    state: R4State,
}
impl<ID: 'static> State<ID> for R4<ID> {
    fn add_message_in(&mut self, _from: &ID, _msg: &Vec<u8>) {}
    fn can_proceed(&self) -> bool {false}
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<ID, Vec<u8>>) {(None, HashMap::new())}
    fn get_id(&self) -> &ID {&self.my_id}
    fn next(self: Box<Self>) -> Box<dyn State<ID>> {self}
}

#[cfg(test)]
mod tests;