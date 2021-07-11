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

pub struct NoMessagesRound<F, K>
where
    K: Behave,
{
    pub round: Box<dyn Executer<FinalOutput = F, Index = K>>,
    pub party_count: usize,
    pub index: Index<K>,
}
