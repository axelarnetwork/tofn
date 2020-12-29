//! Object oriented design pattern from https://doc.rust-lang.org/book/ch17-03-oo-design-patterns.html
pub mod gg20;

use std::collections::HashMap;

pub struct Protocol {
    state: Option<Box<dyn State>>,
}

impl Protocol {
    pub fn next(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.next())
        }
    }
    pub fn add_message_in(&mut self, from: &str, msg: &Vec<u8>) {
        self.state.as_mut().unwrap().add_message_in(from, msg)
    }
    pub fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>) {
        self.state.as_ref().unwrap().get_messages_out()
    }
    pub fn can_proceed(&self) -> bool {
        self.state.as_ref().unwrap().can_proceed()
    }
}

pub trait State {
    // type ID;
    fn add_message_in(&mut self, from: &str, msg: &Vec<u8>); // either bcast or p2p
    fn get_messages_out(&self) -> (Option<Vec<u8>>, HashMap<String, Vec<u8>>); // (bcast, p2p)
    fn can_proceed(&self) -> bool;
    fn next(self: Box<Self>) -> Box<dyn State>;
}

#[cfg(test)]
mod tests;