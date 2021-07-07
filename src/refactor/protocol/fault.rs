#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}
