use crate::{
    fillvec::FillVec,
    protocol::{MsgBytes, Protocol, Result},
};
use serde::{Deserialize, Serialize};

mod stateless;
use stateless::*;

enum State {
    New,
    R1(R1State),
    R2(R2State),
    R3(R3State),
    Done,
}
use State::*;

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p,
    R3Bcast,
}
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}
pub struct Keygen {
    state: State,

    // protocol-wide data
    share_count: usize,
    threshold: usize,
    my_index: usize,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    out_r1bcast: Option<MsgBytes>,
    out_r2bcast: Option<MsgBytes>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r3bcast: Option<MsgBytes>,
    final_output: Option<MsgBytes>, // TODO why serialize result?

    in_r1bcasts: FillVec<R1Bcast>,
    in_r2bcasts: FillVec<R2Bcast>,
    in_r2p2ps: FillVec<R2P2p>,
    in_r3bcasts: FillVec<R3Bcast>,
}

impl Keygen {
    pub fn new(share_count: usize, threshold: usize, my_index: usize) -> Self {
        Self {
            state: New,
            share_count,
            threshold,
            my_index,
            out_r1bcast: None,
            out_r2bcast: None,
            out_r2p2ps: None,
            out_r3bcast: None,
            final_output: None,
            in_r1bcasts: FillVec::with_capacity(share_count),
            in_r2bcasts: FillVec::with_capacity(share_count),
            in_r2p2ps: FillVec::with_capacity(share_count),
            in_r3bcasts: FillVec::with_capacity(share_count),
        }
    }
    fn is_full<T>(&self, v: &FillVec<T>) -> bool {
        // have we received a message from all other parties?
        (v.is_none(self.my_index) && v.some_count() >= self.share_count - 1)
            || v.some_count() >= self.share_count
    }
}

impl Protocol for Keygen {
    fn next(&mut self) -> Result {
        if !self.can_proceed() {
            return Err(From::from("can't prceed yet"));
        }
        self.state = match &self.state {
            New => {
                let (r1state, out_r1bcast_deserialized) =
                    r1::start(self.share_count, self.threshold, self.my_index);
                self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R1Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&out_r1bcast_deserialized)?,
                })?);
                R1(r1state)
            }

            R1(state) => {
                let (r2state, out_r2bcast_deserialized, out_r2p2ps_deserialized) =
                    r2::execute(state, self.in_r1bcasts.vec_ref());
                self.out_r2bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R2Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&out_r2bcast_deserialized)?,
                })?);
                let mut out_r2p2ps = Vec::with_capacity(self.share_count);
                for opt in out_r2p2ps_deserialized {
                    if let Some(p2p) = opt {
                        out_r2p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R2P2p,
                            from: self.my_index,
                            payload: bincode::serialize(&p2p)?,
                        })?));
                    } else {
                        out_r2p2ps.push(None);
                    }
                }
                self.out_r2p2ps = Some(out_r2p2ps);
                R2(r2state)
            }

            R2(state) => {
                let (r3state, out_r3bcast_deserialized) =
                    r3::execute(state, self.in_r2bcasts.vec_ref(), self.in_r2p2ps.vec_ref());
                self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R3Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&out_r3bcast_deserialized)?,
                })?);
                R3(r3state)
            }

            R3(state) => {
                let final_output = r4::execute(state, self.in_r3bcasts.vec_ref());
                self.final_output = Some(bincode::serialize(&final_output)?);
                Done
            }
            _ => todo!(),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> Result {
        // TODO match self.state
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        match msg_meta.msg_type {
            MsgType::R1Bcast => self
                .in_r1bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R2Bcast => self
                .in_r2bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R2P2p => self
                .in_r2p2ps
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R3Bcast => self
                .in_r3bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
        };
        Ok(())
    }

    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        match self.state {
            New => &None,
            R1(_) => &self.out_r1bcast,
            R2(_) => &self.out_r2bcast,
            R3(_) => &self.out_r3bcast,
            Done => &None,
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.state {
            New => &None,
            R1(_) => &None,
            R2(_) => &self.out_r2p2ps,
            R3(_) => &None,
            Done => &None,
        }
    }

    fn can_proceed(&self) -> bool {
        match self.state {
            New => true,
            R1(_) => self.is_full(&self.in_r1bcasts),
            R2(_) => self.is_full(&self.in_r2bcasts) && self.is_full(&self.in_r2p2ps),
            R3(_) => self.is_full(&self.in_r3bcasts),
            Done => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.state, Done)
    }

    fn get_result(&self) -> &Option<MsgBytes> {
        &self.final_output
    }
}

#[cfg(test)]
mod tests;
