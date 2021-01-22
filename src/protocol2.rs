pub type MsgBytes = Vec<u8>;

pub trait Protocol2 {
    fn next(&mut self); // TODO return an error if we can't proceed?
    fn set_msg_in(&mut self, msg: &[u8]) -> Result<(), Box<dyn std::error::Error>>; // TODO error type?
    fn get_bcast_out(&self) -> Option<MsgBytes>;
    fn get_p2p_out(&self) -> Vec<Option<MsgBytes>>;
    fn can_proceed(&self) -> bool;
    fn done(&self) -> bool;
    fn get_result(&self) -> Option<MsgBytes>; // TODO why serialize result? return generic R instead?
}
