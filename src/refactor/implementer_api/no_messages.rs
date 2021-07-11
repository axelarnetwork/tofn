use crate::vecmap::{Behave, Index};

use super::ProtocolBuilder;

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}
