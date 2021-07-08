use crate::vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, Index};
use tracing::warn;

use self::executer::{ProtocolBuilder, RoundExecuterRaw};

use super::{BytesVec, TofnResult};

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(ProtocolRound<F, K>),
    Done(F),
}

pub struct ProtocolRound<F, K>
where
    K: Behave,
{
    round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
    party_count: usize,
    index: Index<K>,
    bcast_out: Option<TofnResult<BytesVec>>,
    p2ps_out: Option<TofnResult<HoleVecMap<K, BytesVec>>>,
    bcasts_in: Option<FillVecMap<K, BytesVec>>,
    p2ps_in: Option<FillP2ps<K, BytesVec>>,
}

impl<F, K> ProtocolRound<F, K>
where
    K: Behave,
{
    pub fn new(
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
        bcast_out: Option<TofnResult<BytesVec>>,
        p2ps_out: Option<TofnResult<HoleVecMap<K, BytesVec>>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index.as_usize() < party_count);
        if let Some(Ok(ref p2ps)) = p2ps_out {
            assert_eq!(p2ps.len(), party_count);
        }

        // we expect to receive (bcast,p2p) messages if and only if (bcasts_in,p2ps_in) is Some
        let bcasts_in = bcast_out
            .as_ref()
            .map(|_| FillVecMap::with_size(party_count));
        let p2ps_in = p2ps_out.as_ref().map(|_| FillP2ps::with_size(party_count));

        Self {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out,
            bcasts_in,
            p2ps_in,
        }
    }
    pub fn bcast_out(&self) -> &Option<TofnResult<BytesVec>> {
        &self.bcast_out
    }
    pub fn p2ps_out(&self) -> &Option<TofnResult<HoleVecMap<K, BytesVec>>> {
        &self.p2ps_out
    }
    pub fn bcast_in(&mut self, from: Index<K>, bytes: &[u8]) {
        if let Some(ref mut bcasts_in) = self.bcasts_in {
            // TODO range check
            bcasts_in.set_warn(from, bytes.to_vec());
        } else {
            warn!("`bcast_in` called but no bcasts expected; discarding `bytes`");
        }
    }
    pub fn p2p_in(&mut self, from: Index<K>, to: Index<K>, bytes: &[u8]) {
        if let Some(ref mut p2ps_in) = self.p2ps_in {
            // TODO range checks
            p2ps_in.set_warn(from, to, bytes.to_vec());
        } else {
            warn!("`p2p_in` called but no p2ps expected; discaring `bytes`");
        }
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        let expecting_more_bcasts = match self.bcasts_in {
            Some(ref bcasts_in) => !bcasts_in.is_full(),
            None => false,
        };
        if expecting_more_bcasts {
            return true;
        }
        let expecting_more_p2ps = match self.p2ps_in {
            Some(ref p2ps_in) => !p2ps_in.is_full(),
            None => false,
        };
        expecting_more_p2ps
    }
    pub fn execute_next_round(self) -> Protocol<F, K> {
        match self.round.execute_raw(
            self.party_count,
            self.index,
            self.bcasts_in.unwrap_or_else(|| FillVecMap::with_size(0)), // TODO accept Option instead
            self.p2ps_in.unwrap_or_else(|| FillP2ps::with_size(0)), // TODO accept Option instead
        ) {
            ProtocolBuilder::NotDone(builder) => Protocol::NotDone(ProtocolRound::new(
                builder.round,
                self.party_count,
                self.index,
                builder.bcast_out,
                builder.p2ps_out,
            )),
            ProtocolBuilder::Done(output) => Protocol::Done(output),
        }
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> Index<K> {
        self.index
    }

    #[cfg(test)]
    pub fn round(&self) -> &Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>> {
        &self.round
    }
}

pub mod executer;
mod fault;
pub use fault::Fault;
