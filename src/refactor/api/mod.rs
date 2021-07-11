//! TODO traits only here, rename to `api` or `traits` or something.
use crate::vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, Index};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::protocol_round::{
    bcast_and_p2p::executer::RoundExecuterRaw, no_messages, ProtocolBuilder, RoundBuilder,
};

pub type TofnResult<T> = Result<T, String>;
pub type BytesVec = Vec<u8>;

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(Round<F, K>),
    Done(ProtocolOutput<F, K>),
}

pub type ProtocolOutput<F, K> = Result<F, FillVecMap<K, Fault>>;

pub enum Round<F, K>
where
    K: Behave,
{
    BcastAndP2p {
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
        bcasts_in: Option<FillVecMap<K, BytesVec>>,
        p2ps_in: Option<FillP2ps<K, BytesVec>>,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}

impl<F, K> Round<F, K>
where
    K: Behave,
{
    pub fn new_bcast_and_p2p(
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

        Round::BcastAndP2p {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out,
            bcasts_in,
            p2ps_in,
        }
    }

    pub fn bcast_out(&self) -> &Option<BytesVec> {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index: _,
                bcast_out,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in: _,
            } => bcast_out,
            Round::NoMessages {
                round: _,
                party_count: _,
                index: _,
            } => &None,
        }
    }
    pub fn p2ps_out(&self) -> &Option<HoleVecMap<K, BytesVec>> {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out,
                bcasts_in: _,
                p2ps_in: _,
            } => p2ps_out,
            Round::NoMessages {
                round: _,
                party_count: _,
                index: _,
            } => &None,
        }
    }
    pub fn bcast_in(&mut self, from: Index<K>, bytes: &[u8]) {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in,
                p2ps_in: _,
            } => {
                if let Some(ref mut bcasts_in) = bcasts_in {
                    // TODO range check
                    bcasts_in.set_warn(from, bytes.to_vec());
                } else {
                    warn!("`bcast_in` called but no bcasts expected; discarding `bytes`");
                }
            }
            Round::NoMessages {
                round: _,
                party_count: _,
                index: _,
            } => warn!("`bcast_in` called but no bcasts expected; discarding `bytes`"),
        }
    }
    pub fn p2p_in(&mut self, from: Index<K>, to: Index<K>, bytes: &[u8]) {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in,
            } => {
                if let Some(ref mut p2ps_in) = p2ps_in {
                    // TODO range checks
                    p2ps_in.set_warn(from, to, bytes.to_vec());
                } else {
                    warn!("`p2p_in` called but no p2ps expected; discaring `bytes`");
                }
            }
            Round::NoMessages {
                round: _,
                party_count: _,
                index: _,
            } => warn!("`p2p_in` called but no p2ps expected; discaring `bytes`"),
        }
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in,
                p2ps_in,
            } => {
                let expecting_more_bcasts = match bcasts_in {
                    Some(ref bcasts_in) => !bcasts_in.is_full(),
                    None => false,
                };
                if expecting_more_bcasts {
                    return true;
                }
                let expecting_more_p2ps = match p2ps_in {
                    Some(ref p2ps_in) => !p2ps_in.is_full(),
                    None => false,
                };
                expecting_more_p2ps
            }
            Round::NoMessages {
                round: _,
                party_count: _,
                index: _,
            } => false,
        }
    }
    pub fn execute_next_round(self) -> Protocol<F, K> {
        match self {
            Round::BcastAndP2p {
                round,
                party_count,
                index,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in,
                p2ps_in,
            } => {
                match round.execute_raw(
                    party_count,
                    index,
                    bcasts_in.unwrap_or_else(|| FillVecMap::with_size(0)), // TODO accept Option instead
                    p2ps_in.unwrap_or_else(|| FillP2ps::with_size(0)), // TODO accept Option instead
                ) {
                    ProtocolBuilder::NotDone(builder) => match builder {
                        RoundBuilder::BcastAndP2p {
                            round,
                            bcast_out,
                            p2ps_out,
                        } => Protocol::NotDone(Round::new_bcast_and_p2p(
                            round,
                            party_count,
                            index,
                            bcast_out,
                            p2ps_out,
                        )),
                    },
                    ProtocolBuilder::Done(output) => Protocol::Done(output),
                }
            }
            Round::NoMessages {
                round,
                party_count,
                index,
            } => match round.execute(party_count, index) {
                ProtocolBuilder::NotDone(builder) => todo!("same as BcastAndP2p"),
                ProtocolBuilder::Done(output) => Protocol::Done(output),
            },
        }
    }
    pub fn party_count(&self) -> usize {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in: _,
            } => *party_count,
            Round::NoMessages {
                round: _,
                party_count,
                index: _,
            } => *party_count,
        }
    }
    pub fn index(&self) -> Index<K> {
        match self {
            Round::BcastAndP2p {
                round: _,
                party_count: _,
                index,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in: _,
            } => *index,
            Round::NoMessages {
                round: _,
                party_count: _,
                index,
            } => *index,
        }
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match self {
            Round::BcastAndP2p {
                round,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in: _,
            } => round.as_any(),
            Round::NoMessages {
                round,
                party_count: _,
                index: _,
            } => round.as_any(),
        }
    }
}
