use std::result;

pub type MsgBytes = Vec<u8>;
pub type Result = std::result::Result<(), Box<dyn std::error::Error>>; // TODO custom error type

pub trait Protocol2 {
    fn next(&mut self) -> Result;
    fn set_msg_in(&mut self, msg: &[u8]) -> Result;
    fn get_bcast_out(&self) -> &Option<MsgBytes>;
    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>>;
    fn can_proceed(&self) -> bool;
    fn done(&self) -> bool;
    fn get_result(&self) -> &Option<MsgBytes>; // TODO why serialize result? return generic R instead?
}
