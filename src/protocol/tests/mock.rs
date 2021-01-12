//! Traits for mock tests
//! ABANDONED
// use super::*;

pub trait Party {
    fn execute();
    fn msg_in(from: &str, msg: &[u8]);
}

pub trait Deliverer {
    fn deliver(&self);
}

pub trait Transport<ID>: Deliverer {
    fn add_party(p: &impl Party);
    fn execute_all();
}
