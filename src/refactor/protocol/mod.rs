use crate::{
    fillvec::FillVec,
    vecmap::{fillvecmap::FillVecMap, Index},
};
use tracing::warn;

use self::executer::RoundExecuter;

use super::BytesVec;

// TODO is it really worth the trouble to make this enum generic?
// Maybe it's best just to duplicate it
pub type Protocol<F, I> = GenericProtocol<ProtocolRound<F, I>, F>;

/// Why trait bound `G: HasTypeParameter<TypeParameter = F>`?
/// We want to write `G<F>` as in:
/// ```compile_fail
/// pub enum GenericProtocol<G, F> {
///     NotDone(G<F>), // ERROR
///     Done(F),
/// }
/// ```
/// but this is not supported by Rust

pub enum GenericProtocol<G, F>
where
    G: HasTypeParameter<TypeParameter = F>,
{
    NotDone(G),
    Done(F),
}

/// work-around for higher kinded types (HKT):
/// * https://stackoverflow.com/a/41509242
/// * https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md
/// * https://github.com/rust-lang/rust/issues/44265
pub trait HasTypeParameter {
    type TypeParameter;
}

impl<F, I> HasTypeParameter for ProtocolRound<F, I> {
    type TypeParameter = F;
}

pub struct ProtocolRound<F, I> {
    round: Box<dyn RoundExecuter<FinalOutput = F, Index = I>>,
    party_count: usize,
    index: usize,
    bcast_out: Option<Vec<u8>>,
    p2ps_out: FillVec<Vec<u8>>, // TODO FillVec with hole?
    bcasts_in: FillVecMap<I, BytesVec>,
    p2ps_in: Vec<FillVec<Vec<u8>>>, // TODO FillVec with hole?
}

impl<F, I> ProtocolRound<F, I> {
    pub fn new(
        round: Box<dyn RoundExecuter<FinalOutput = F, Index = I>>,
        party_count: usize,
        index: usize,
        bcast_out: Option<Vec<u8>>,
        p2ps_out: Option<FillVec<Vec<u8>>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index < party_count);
        if let Some(ref p2ps) = p2ps_out {
            assert_eq!(p2ps.len(), party_count);
        }

        let bcasts_in_len = match bcast_out {
            Some(_) => party_count,
            None => 0,
        };
        let p2ps_in_len = match p2ps_out {
            Some(_) => party_count,
            None => 0,
        };
        let p2ps_out_bytes = match p2ps_out {
            Some(p2ps) => p2ps,
            None => FillVec::with_len(0),
        };
        Self {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out: p2ps_out_bytes,
            bcasts_in: FillVecMap::with_size(bcasts_in_len),
            p2ps_in: vec![FillVec::with_len(p2ps_in_len); p2ps_in_len],
        }
    }
    pub fn bcast_out(&self) -> &Option<Vec<u8>> {
        &self.bcast_out
    }
    pub fn p2ps_out(&self) -> &FillVec<Vec<u8>> {
        &self.p2ps_out
    }
    pub fn bcast_in(&mut self, from: Index<I>, bytes: &[u8]) {
        if !self.expecting_bcasts_in() {
            warn!("`bcast_in` called but no bcasts expected; discarding `bytes`");
            return;
        }
        // TODO range check
        self.bcasts_in.set_warn(from, bytes.to_vec());
    }
    pub fn p2p_in(&mut self, from: usize, to: usize, bytes: &[u8]) {
        if !self.expecting_p2ps_in() {
            warn!("`p2p_in` called but no p2ps expected; discaring `bytes`");
            return;
        }
        // TODO range check should occur at a lower level
        if from >= self.p2ps_in.len() {
            warn!(
                "`from` index {} out of range {}, discarding `msg`",
                from,
                self.p2ps_in.len()
            );
            return;
        }
        if to >= self.p2ps_in[from].len() {
            warn!(
                "`to` index {} out of range {}, discarding `msg`",
                to,
                self.p2ps_in[from].len()
            );
            return;
        }
        self.p2ps_in[from].overwrite_warn(to, bytes.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        let bcasts_full = self.bcasts_in.is_full();
        let p2ps_full = self
            .p2ps_in
            .iter()
            .enumerate()
            .all(|(i, p)| p.is_full_except(i));
        !bcasts_full && self.expecting_bcasts_in() || !p2ps_full && self.expecting_p2ps_in()
    }
    pub fn execute_next_round(self) -> Protocol<F, I> {
        self.round
            .execute(self.party_count, self.index, self.bcasts_in, self.p2ps_in)
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> usize {
        self.index
    }

    fn expecting_bcasts_in(&self) -> bool {
        self.bcasts_in.size() != 0
    }
    fn expecting_p2ps_in(&self) -> bool {
        !self.p2ps_in.len() != 0
    }

    #[cfg(test)]
    pub fn round(&self) -> &Box<dyn RoundExecuter<FinalOutput = F, Index = I>> {
        &self.round
    }
}

pub mod executer;
