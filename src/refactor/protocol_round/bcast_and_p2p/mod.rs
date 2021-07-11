use tracing::warn;

use crate::{
    refactor::api::{BytesVec, Protocol, Round},
    vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, Index},
};

use super::{ProtocolBuilder, RoundBuilder};

pub struct BcastAndP2p<F, K>
where
    K: Behave,
{
    round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
    party_count: usize,
    index: Index<K>,
    bcast_out: Option<BytesVec>,
    p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    bcasts_in: Option<FillVecMap<K, BytesVec>>,
    p2ps_in: Option<FillP2ps<K, BytesVec>>,
}

impl<F, K> BcastAndP2p<F, K>
where
    K: Behave,
{
    pub fn new(
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index.as_usize() < party_count);
        if let Some(ref p2ps) = p2ps_out {
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
}
impl<F, K> Round for BcastAndP2p<F, K>
where
    // Why 'static? Because `execute_next_round` returns `Protocol`,
    // which leads to this problem: https://stackoverflow.com/a/40053651
    K: Behave + 'static,
    F: 'static,
{
    type FinalOutput = F;
    type Index = K;

    fn bcast_out(&self) -> &Option<BytesVec> {
        &self.bcast_out
    }
    fn p2ps_out(&self) -> &Option<HoleVecMap<K, BytesVec>> {
        &self.p2ps_out
    }
    fn bcast_in(&mut self, from: Index<K>, bytes: &[u8]) {
        if let Some(ref mut bcasts_in) = self.bcasts_in {
            // TODO range check
            bcasts_in.set_warn(from, bytes.to_vec());
        } else {
            warn!("`bcast_in` called but no bcasts expected; discarding `bytes`");
        }
    }
    fn p2p_in(&mut self, from: Index<K>, to: Index<K>, bytes: &[u8]) {
        if let Some(ref mut p2ps_in) = self.p2ps_in {
            // TODO range checks
            p2ps_in.set_warn(from, to, bytes.to_vec());
        } else {
            warn!("`p2p_in` called but no p2ps expected; discaring `bytes`");
        }
    }
    fn expecting_more_msgs_this_round(&self) -> bool {
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
    fn execute_next_round(self: Box<Self>) -> Protocol<Self::FinalOutput, Self::Index> {
        match self.round.execute_raw(
            self.party_count,
            self.index,
            self.bcasts_in.unwrap_or_else(|| FillVecMap::with_size(0)), // TODO accept Option instead
            self.p2ps_in.unwrap_or_else(|| FillP2ps::with_size(0)), // TODO accept Option instead
        ) {
            ProtocolBuilder::NotDone(builder) => match builder {
                RoundBuilder::BcastAndP2p {
                    round,
                    bcast_out,
                    p2ps_out,
                } => Protocol::NotDone(Box::new(BcastAndP2p::new(
                    round,
                    self.party_count,
                    self.index,
                    bcast_out,
                    p2ps_out,
                ))),
            },
            ProtocolBuilder::Done(output) => Protocol::Done(output),
        }
    }
    fn party_count(&self) -> usize {
        self.party_count
    }
    fn index(&self) -> Index<K> {
        self.index
    }

    #[cfg(test)]
    fn round(&self) -> &Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>> {
        &self.round
    }
}

pub mod executer;
use executer::RoundExecuterRaw;
