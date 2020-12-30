use super::*;
use crate::protocol::{
    self,
    tests::{Party, Deliverer}
};

struct HappyParty<'a, ID> {
    me: protocol::Protocol<ID>,
    transport: &'a dyn Deliverer,
}

// TODO replace args with a protobuf grpc keygeninfo struct
pub fn new_party<'a, ID: 'static>(party_ids: &'a Vec<ID>, my_party_id_index: usize, threshold: usize, transport: &'a dyn Deliverer ) -> impl Party<ID> + 'a
    where ID: Eq + Hash + Ord + Clone + Debug
{
    HappyParty::<'a>{
        me: new(party_ids, my_party_id_index, threshold),
        transport,
    }
}

impl<'a, ID> Party<ID> for HappyParty<'a, ID> {
    fn execute() {}
	fn msg_in(from: &ID, msg: &Vec<u8>) {}
}

#[test]
fn it_works() {}