pub mod keygen;
pub mod sign;
mod vss;

#[derive(Clone, Debug, PartialEq)]
pub enum GeneralMsgType {
    KeygenMsgType { msg_type: keygen::MsgType },
    SignMsgType { msg_type: sign::MsgType },
}

#[derive(Clone, Debug, PartialEq)]
pub enum GeneralCrime {
    Stall { msg_type: GeneralMsgType },
}

#[cfg(test)]
mod tests;
