use super::{Sign, Status};

// round 2
pub struct P2p {}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {}

impl Sign {
    pub(super) fn r2(&self) -> (State, Vec<Option<P2p>>) {
        assert!(matches!(self.status, Status::R1));
        todo!()
    }
}
