pub type MsgBytes = Vec<u8>;
pub type Result = std::result::Result<(), Box<dyn std::error::Error>>; // TODO custom error type

pub trait Protocol {
    fn next_round(&mut self) -> Result;
    fn set_msg_in(&mut self, msg: &[u8]) -> Result;
    fn get_bcast_out(&self) -> &Option<MsgBytes>; // TODO Option<&MsgBytes> instead
    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>>; // TODO Option<&Vec<Option<MsgBytes>>> instead
    fn expecting_more_msgs_this_round(&self) -> bool;
    fn done(&self) -> bool;
}

pub mod gg20;
#[cfg(test)]
mod tests;
