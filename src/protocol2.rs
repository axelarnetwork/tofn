use crate::protocol::gg20::keygen::stateless::{R1Bcast, R2Bcast, R2P2p, R3Bcast};
use std::collections::HashMap;

// Protocol2 contains all the methods needed by rust-tssd grpc daemon to run **any possible protocol!**
pub trait Protocol2 {
    // get_state is the only method without a default implementation
    // it's a simple getter, so impl boilerplate is minimal (example below)
    fn get_state(&self) -> &dyn State2;

    // cruft: default implementations to pass through calls to underlying State methods
    // thankfully, this does not need to be repeated for each concrete impl
    // missing methods: add_message_in, next, which need more cruft but you get the idea
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        self.get_state().get_messages_out()
    }
    fn get_id(&self) -> &str {
        self.get_state().get_id()
    }
    fn can_proceed(&self) -> bool {
        self.get_state().can_proceed()
    }
    fn done(&self) -> bool {
        self.get_state().done()
    }
}

// concrete protocol
pub struct KeygenProtocol {
    state: Option<Box<dyn State2>>, // same as before

    // this data could be keygen-specific
    party_ids: Vec<String>, // share_count is implicitly party_ids.len()
    my_id_index: usize,     // my_id is implicitly party_ids[my_id_index]
    threshold: usize,

    // not much different for outgoing msgs
    // as discussed, hashmap has the form:
    // HashMap< (round,bcast/p2p,path), HashMap< [index into party_ids], [serialized msg]>>
    // for now we somehow encode (round,bcast/p2p,path) as a usize but this might change
    // NOTE: inner usize type indexes into party_ids instead of copying the String.
    //   I prefer to use references &String or &str into party_ids but Rust does not allow a struct to refer to itself https://stackoverflow.com/questions/30823880/struct-that-owns-some-data-and-a-reference-to-the-data
    out_msgs: HashMap<usize, HashMap<usize, Vec<u8>>>,

    // incoming msgs are different from what we discussed
    // as discussed, we prefer to deserialize incoming msgs immediately then store them deserialized
    //   that means we need hashmaps with protocol-specific concrete value types
    //   fortunately, this design allows us to do it!
    // format: HashMap< [index into party_ids], [concrete msg]>
    in_msgs_r1bcast: HashMap<usize, R1Bcast>,
    in_msgs_r2bcast: HashMap<usize, R2Bcast>,
    in_msgs_r2p2p: HashMap<usize, R2P2p>,
    in_msgs_r3bcast: HashMap<usize, R3Bcast>,
    // if desired we can split out_msgs into distinct 1-level hashmaps just like we did for in_msgs
    //   the only difference is that all value types will be Vec<u8>
    //   this option eliminates the need to encode (round,bcast/p2p,path) as a usize
}

// minimal boilerplate for each concrete protocol
impl Protocol2 for KeygenProtocol {
    fn get_state(&self) -> &dyn State2 {
        self.state.as_ref().unwrap().as_ref()
    }
}

impl KeygenProtocol {
    // constructor as before
    // pub fn new(ids: &[String], my_id_index: usize, threshold: usize) -> impl Protocol2 {
    //     Self {
    //         // TODO initialize each field
    //         state: (),
    //         party_ids: ids.to_vec(),
    //         my_id_index,
    //         threshold,
    //         out_msgs: (),
    //         in_msgs_r1bcast: (),
    //         in_msgs_r2bcast: (),
    //         in_msgs_r2p2p: (),
    //         in_msgs_r3bcast: (),
    //     }
    // }
}

// same as before
pub trait State2 {
    // fn add_message_in(&mut self, from: &str, msg: &[u8]); // either bcast or p2p
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>); // (bcast, p2p)
    fn get_id(&self) -> &str; // TODO delete this method?
    fn can_proceed(&self) -> bool;
    // fn next(self: Box<Self>) -> Box<dyn State2>;
    fn done(&self) -> bool;
}
