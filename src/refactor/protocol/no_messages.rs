use super::{
    api::TofnResult,
    implementer_api::{ProtocolBuilder, RoundInfo},
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index;
    type PartyIndex;
    fn execute(
        self: Box<Self>,
        info: &RoundInfo<Self::Index, Self::PartyIndex>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index, Self::PartyIndex>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}
