use super::{Keygen, Status::*};
use crate::protocol::{MsgBytes, Protocol, ProtocolResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p { to: usize },
    R3Bcast,
}

// TODO identical to keygen::MsgMeta except for MsgType---use generic
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}

impl Protocol for Keygen {
    fn next_round(&mut self) -> ProtocolResult {
        if self.expecting_more_msgs_this_round() {
            return Err(From::from("can't prceed yet"));
        }
        // TODO refactor repeated code!
        self.status = match self.status {
            New => {
                let (state, bcast) = self.r1();
                self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R1Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r1state = Some(state);
                R1
            }

            R1 => {
                let (state, bcast, p2ps) = self.r2();
                self.out_r2bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R2Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r2p2ps = Vec::with_capacity(self.share_count);
                for (to, opt) in p2ps.into_vec().into_iter().enumerate() {
                    if let Some(p2p) = opt {
                        out_r2p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R2P2p { to },
                            from: self.my_index,
                            payload: bincode::serialize(&p2p)?,
                        })?));
                    } else {
                        out_r2p2ps.push(None);
                    }
                }
                self.out_r2p2ps = Some(out_r2p2ps);
                self.r2state = Some(state);
                R2
            }

            R2 => {
                let (state, bcast) = self.r3();
                self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R3Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r3state = Some(state);
                R3
            }

            R3 => {
                self.final_output = Some(self.r4());
                Done
            }
            Done => return Err(From::from("already done")),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> ProtocolResult {
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
            MsgType::R2P2p { to } => self.in_all_r2p2ps[msg_meta.from]
                .insert(to, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R3Bcast => self
                .in_r3bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
        };
        Ok(())
    }

    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        match self.status {
            New => &None,
            R1 => &self.out_r1bcast,
            R2 => &self.out_r2bcast,
            R3 => &self.out_r3bcast,
            Done => &None,
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.status {
            New => &None,
            R1 => &None,
            R2 => &self.out_r2p2ps,
            R3 => &None,
            Done => &None,
        }
    }

    fn expecting_more_msgs_this_round(&self) -> bool {
        let me = self.my_index;
        match self.status {
            New => false,
            R1 => !self.in_r1bcasts.is_full_except(me),
            R2 => {
                if !self.in_r2bcasts.is_full_except(me) {
                    return true;
                }
                for (i, in_r2p2ps) in self.in_all_r2p2ps.iter().enumerate() {
                    if i == me {
                        continue;
                    }
                    if !in_r2p2ps.is_full_except(i) {
                        return true;
                    }
                }
                false
            }
            R3 => !self.in_r3bcasts.is_full_except(me),
            Done => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.status, Done)
    }
}
