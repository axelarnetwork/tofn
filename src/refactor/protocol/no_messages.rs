use crate::refactor::collections::{Behave, TypedUsize};

use super::{api::TofnResult, implementer_api::ProtocolBuilder};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: TypedUsize<Self::Index>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}
