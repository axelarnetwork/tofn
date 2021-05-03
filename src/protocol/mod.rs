pub type MsgBytes = Vec<u8>;
pub type ProtocolResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>; // TODO custom error type

pub trait Protocol {
    fn next_round(&mut self) -> ProtocolResult;
    fn set_msg_in(&mut self, msg: &[u8]) -> ProtocolResult;
    fn get_bcast_out(&self) -> &Option<MsgBytes>; // TODO Option<&MsgBytes> instead
    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>>; // TODO Option<&Vec<Option<MsgBytes>>> instead
    fn expecting_more_msgs_this_round(&self) -> bool;
    fn done(&self) -> bool;
}

// TODO where to put this?
#[derive(Debug, Clone, PartialEq)]
pub enum CrimeType {
    Malicious,    // cryptographic evidence of malice (eg. zk proof fail to verify)
    NonMalicious, // no cryptographic evidence of malice (eg. timeout)
}
#[derive(Debug, Clone, PartialEq)]
pub struct Criminal {
    pub index: usize,
    pub crime_type: CrimeType,
}

pub mod gg20;
#[cfg(test)]
mod tests;
