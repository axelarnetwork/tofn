//! Traits for mock tests
// use super::*;

pub trait Party<ID> {
    fn execute();
	fn msg_in(from: &ID, msg: &Vec<u8>);
}

pub trait Deliverer {
    fn deliver(&self);
}

pub trait Transport<ID>: Deliverer {
    fn add_party(p: &impl Party<ID>);
    fn execute_all();
}

