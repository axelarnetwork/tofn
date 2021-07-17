use super::{
    api::TofnResult,
    implementer_api::{ProtocolBuilder, ProtocolInfo},
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}
