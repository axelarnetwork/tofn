use crate::{
    fillvec::FillVec,
    vecmap::{fillvecmap::FillVecMap, Index},
};
use tracing::warn;

use self::executer::{ProtocolBuilder, RoundExecuter};

use super::BytesVec;

pub enum Protocol<F, K> {
    NotDone(ProtocolRound<F, K>),
    Done(F),
}

pub struct ProtocolRound<F, K> {
    round: Box<dyn RoundExecuter<FinalOutput = F, Index = K>>,
    party_count: usize,
    index: usize,
    bcast_out: Option<BytesVec>,
    p2ps_out: Option<FillVec<Vec<u8>>>, // TODO FillVec with hole?
    bcasts_in: Option<FillVecMap<K, BytesVec>>,
    p2ps_in: Option<Vec<FillVec<Vec<u8>>>>, // TODO FillVec with hole?
}

impl<F, K> ProtocolRound<F, K> {
    pub fn new(
        round: Box<dyn RoundExecuter<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: usize,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<FillVec<Vec<u8>>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index < party_count);
        if let Some(ref p2ps) = p2ps_out {
            assert_eq!(p2ps.len(), party_count);
        }

        let bcasts_in = bcast_out
            .as_ref()
            .map(|_| FillVecMap::with_size(party_count));
        let p2ps_in = p2ps_out
            .as_ref()
            .map(|_| vec![FillVec::with_len(party_count); party_count]);

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
    pub fn bcast_out(&self) -> &Option<Vec<u8>> {
        &self.bcast_out
    }
    pub fn p2ps_out(&self) -> &Option<FillVec<Vec<u8>>> {
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
    pub fn p2p_in(&mut self, from: usize, to: usize, bytes: &[u8]) {
        if let Some(ref mut p2ps_in) = self.p2ps_in {
            // TODO range checks
            p2ps_in[from].overwrite_warn(to, bytes.to_vec());
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
            Some(ref p2ps_in) => !p2ps_in.iter().enumerate().all(|(i, p)| p.is_full_except(i)),
            None => false,
        };
        expecting_more_p2ps
    }
    pub fn execute_next_round(self) -> Protocol<F, K> {
        match self.round.execute(
            self.party_count,
            self.index,
            self.bcasts_in.unwrap_or_else(|| FillVecMap::with_size(0)),
            self.p2ps_in.unwrap_or_else(|| Vec::new()),
        ) {
            ProtocolBuilder::NotDone(builder) => {
                let bcast_out = if let Some(Ok(bytes)) = builder.bcast_out {
                    Some(bytes)
                } else {
                    None
                };
                Protocol::NotDone(ProtocolRound::new(
                    builder.round,
                    self.party_count,
                    self.index,
                    bcast_out,
                    builder.p2ps_out,
                ))
            }
            ProtocolBuilder::Done(output) => Protocol::Done(output),
        }
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> usize {
        self.index
    }

    #[cfg(test)]
    pub fn round(&self) -> &Box<dyn RoundExecuter<FinalOutput = F, Index = K>> {
        &self.round
    }
}

pub mod executer;
