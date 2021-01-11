//! Object oriented design pattern from https://doc.rust-lang.org/book/ch17-03-oo-design-patterns.html
//! plus a generic `R` type for the result of the protocol
pub mod gg20;

use std::collections::HashMap;

pub struct Protocol<R> {
    state: Option<Box<dyn State<Result = R> + Send>>,
}

impl<R> Protocol<R> {
    // TODO implement the iterator trait?
    pub fn next(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.next())
        }
    }
    pub fn add_message_in(&mut self, from: &str, msg: &[u8]) {
        self.state.as_mut().unwrap().add_message_in(from, msg)
    }
    pub fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        self.state.as_ref().unwrap().get_messages_out()
    }
    pub fn get_id(&self) -> &str {
        self.state.as_ref().unwrap().get_id()
    }
    pub fn can_proceed(&self) -> bool {
        self.state.as_ref().unwrap().can_proceed()
    }
    pub fn done(&self) -> bool {
        self.state.as_ref().unwrap().done()
    }
    pub fn get_result(&self) -> Option<R> {
        self.state.as_ref().unwrap().get_result()
    }
}

pub trait State {
    type Result;
    fn add_message_in(&mut self, from: &str, msg: &[u8]); // either bcast or p2p
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>); // (bcast, p2p)
    fn get_id(&self) -> &str; // TODO delete this method?
    fn can_proceed(&self) -> bool;
    fn next(self: Box<Self>) -> Box<dyn State<Result = Self::Result> + Send>;
    fn done(&self) -> bool;
    fn get_result(&self) -> Option<Self::Result> { None }
}

#[cfg(test)]
mod tests;