use super::{Sign, Status::*};
use crate::{
    fillvec::FillVec,
    protocol::{MsgBytes, Protocol, Result},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R1P2p,
    R2P2p,
}

// TODO identical to keygen::MsgMeta except for MsgType---use generic
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}

impl Protocol for Sign {
    fn next_round(&mut self) -> Result {
        if self.expecting_more_msgs_this_round() {
            return Err(From::from("can't prceed yet"));
        }
        // TODO refactor repeated code!
        self.status = match self.status {
            New => {
                let (state, bcast, p2ps) = self.r1();
                self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R1Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r1p2ps = Vec::with_capacity(self.participant_indices.len());
                for opt in p2ps {
                    if let Some(p2p) = opt {
                        out_r1p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R1P2p,
                            from: self.my_participant_index,
                            payload: bincode::serialize(&p2p)?,
                        })?));
                    } else {
                        out_r1p2ps.push(None);
                    }
                }
                self.out_r1p2ps = Some(out_r1p2ps);
                self.r1state = Some(state);
                R1
            }

            R1 => {
                let (state, p2ps) = self.r2();
                let mut out_r2p2ps = Vec::with_capacity(self.participant_indices.len());
                for opt in p2ps {
                    if let Some(p2p) = opt {
                        out_r2p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R2P2p,
                            from: self.my_participant_index,
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

            // R2 => {
            //     let (state, bcast) = self.r3();
            //     self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
            //         msg_type: MsgType::R1Bcast,
            //         from: self.my_participant_index,
            //         payload: bincode::serialize(&bcast)?,
            //     })?);
            // }
            _ => todo!(),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> Result {
        // TODO match self.status
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        match msg_meta.msg_type {
            MsgType::R1Bcast => self
                .in_r1bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R1P2p => self
                .in_r1p2ps
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R2P2p => self
                .in_r2p2ps
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
        };
        Ok(())
    }

    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        match self.status {
            New => &None,
            R1 => &self.out_r1bcast,
            R2 => &None,
            Done => &None,
            _ => todo!(),
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.status {
            New => &None,
            R1 => &self.out_r1p2ps,
            R2 => &self.out_r2p2ps,
            Done => &None,
            _ => todo!(),
        }
    }

    fn expecting_more_msgs_this_round(&self) -> bool {
        let i = self.my_participant_index;
        match self.status {
            New => false,
            R1 => !self.in_r1bcasts.is_full_except(i) || !self.in_r1p2ps.is_full_except(i),
            R2 => !self.in_r2p2ps.is_full_except(i),
            Done => false,
            _ => todo!(),
        }
    }

    fn done(&self) -> bool {
        matches!(self.status, Done)
    }
}
