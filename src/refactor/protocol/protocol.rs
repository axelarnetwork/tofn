use std::vec;

use tracing::{error, warn};

use crate::fillvec::FillVec;
// use serde::{de::DeserializeOwned, Serialize};

pub enum Protocol<F> {
    NotDone(ProtocolRound<F>),
    Done(F),
}

pub trait RoundExecuter: Send + Sync {
    type FinalOutput;
    fn execute(
        self: Box<Self>,
        // TODO add party_count, index
        bcasts_in: FillVec<Vec<u8>>,
        p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> Protocol<Self::FinalOutput>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

pub struct ProtocolRound<F> {
    config: ConfigInternal, // TODO no need for ConfigInternal after I add party_count, index args to `execute`
    round: Box<dyn RoundExecuter<FinalOutput = F>>,
    party_count: usize,
    index: usize,
    bcast_out: Option<Vec<u8>>,
    p2ps_out: FillVec<Vec<u8>>, // TODO FillVec with hole?
    bcasts_in: FillVec<Vec<u8>>,
    p2ps_in: Vec<FillVec<Vec<u8>>>, // TODO FillVec with hole?
}

impl<F> ProtocolRound<F> {
    pub fn new(
        config: Config,
        party_count: usize,
        index: usize,
        round: Box<dyn RoundExecuter<FinalOutput = F>>,
    ) -> Self {
        use Config::*;
        let (party_count, bcast_out, p2ps_out, config_internal) = match config {
            NoMessages => (0, None, FillVec::with_len(0), ConfigInternal::NoMessages),
            BcastOnly {
                bcast_out_bytes,
                party_count,
            } => (
                party_count,
                bcast_out_bytes,
                FillVec::with_len(0),
                ConfigInternal::BcastOnly,
            ),
            P2pOnly { p2ps_out_bytes } => (
                p2ps_out_bytes.len(),
                None,
                p2ps_out_bytes,
                ConfigInternal::P2pOnly,
            ),
            BcastAndP2p {
                bcast_out_bytes,
                p2ps_out_bytes,
            } => (
                p2ps_out_bytes.len(),
                bcast_out_bytes,
                p2ps_out_bytes,
                ConfigInternal::BcastAndP2p,
            ),
        };
        Self {
            config: config_internal,
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out,
            bcasts_in: FillVec::with_len(party_count),
            p2ps_in: vec![FillVec::with_len(party_count); party_count],
        }
    }
    pub fn bcast_out(&self) -> Option<&Vec<u8>> {
        self.bcast_out.as_ref()
    }
    pub fn p2ps_out(&self) -> &FillVec<Vec<u8>> {
        &self.p2ps_out
    }
    pub fn bcast_in(&mut self, from: usize, msg: &[u8]) {
        use ConfigInternal::*;
        if !matches!(self.config, BcastOnly | BcastAndP2p) {
            warn!(
                "`bcast_in` called with `config` {:?}, discarding `msg`",
                self.config
            );
            return;
        }
        if from >= self.bcasts_in.len() {
            warn!(
                "`from` index {} out of range {}, discarding `msg`",
                from,
                self.bcasts_in.len()
            );
            return;
        }
        self.bcasts_in.overwrite_warn(from, msg.to_vec());
    }
    pub fn p2p_in(&mut self, from: usize, to: usize, msg: &[u8]) {
        use ConfigInternal::*;
        if !matches!(self.config, P2pOnly | BcastAndP2p) {
            warn!(
                "`p2p_in` called with `config` {:?}, discarding `msg`",
                self.config
            );
            return;
        }
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
        self.p2ps_in[from].overwrite_warn(to, msg.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        use ConfigInternal::*;
        let bcasts_full = self.bcasts_in.is_full();
        let p2ps_full = self
            .p2ps_in
            .iter()
            .enumerate()
            .all(|(i, p)| p.is_full_except(i));
        match self.config {
            NoMessages => false,
            BcastOnly => !bcasts_full,
            P2pOnly => !p2ps_full,
            BcastAndP2p => !bcasts_full || !p2ps_full,
        }
    }
    pub fn execute_next_round(self) -> Protocol<F> {
        self.round.execute(self.bcasts_in, self.p2ps_in)
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> usize {
        self.index
    }

    #[cfg(test)]
    pub fn round(&self) -> &Box<dyn RoundExecuter<FinalOutput = F>> {
        &self.round
    }
}

#[derive(Debug)]
pub enum Config {
    NoMessages,
    BcastOnly {
        bcast_out_bytes: Option<Vec<u8>>,
        party_count: usize,
    },
    P2pOnly {
        p2ps_out_bytes: FillVec<Vec<u8>>,
    },
    BcastAndP2p {
        bcast_out_bytes: Option<Vec<u8>>,
        p2ps_out_bytes: FillVec<Vec<u8>>,
    },
}

#[derive(Debug)]
enum ConfigInternal {
    NoMessages,
    BcastOnly,
    P2pOnly,
    BcastAndP2p,
}

pub(crate) fn serialize_as_option<T: ?Sized>(value: &T) -> Option<Vec<u8>>
where
    T: serde::Serialize,
{
    let bytes = bincode::serialize(value).ok();
    if bytes.is_none() {
        error!("serialization failure");
    }
    bytes
}
