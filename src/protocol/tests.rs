//! Traits for mock tests
// use super::*;

pub trait Party {
    fn execute();
	fn msg_in(msg: &Vec<u8>);
}

pub trait Deliverer {
    fn deliver();
}

pub trait Transport: Deliverer {
    fn add_party(p: &impl Party);
    fn execute_all();
}

