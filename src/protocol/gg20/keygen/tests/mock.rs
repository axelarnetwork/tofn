//! Mock implementation for happy path keygen
//! ABANDONED
use super::super::*;
use crate::protocol::{
    self,
    tests::mock::{Party, Deliverer}
};

#[allow(dead_code)]
struct HappyParty<'a> {
    me: protocol::Protocol,
    transport: &'a dyn Deliverer,
}

// TODO replace args with a protobuf grpc keygeninfo struct
#[allow(dead_code)]
pub fn new_party<'a>(party_ids: &[String], my_party_id_index: usize, threshold: usize, transport: &'a dyn Deliverer ) -> impl Party + 'a {
    HappyParty{
        me: new_protocol(party_ids, my_party_id_index, threshold),
        transport,
    }
}

impl<'a> Party for HappyParty<'a> {
    fn execute() {}
	fn msg_in(_from: &str, _msg: &[u8]) {}
}