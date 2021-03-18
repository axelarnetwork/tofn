use super::{Sign, Status::*};
use crate::protocol::{MsgBytes, Protocol, ProtocolResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R1P2p { to: usize },
    R2P2p,
    R3Bcast,
    R4Bcast,
    R5Bcast,
    R5P2p,
    R6Bcast,
    R7Bcast,
}

// TODO identical to keygen::MsgMeta except for MsgType---use generic
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}

impl Protocol for Sign {
    fn next_round(&mut self) -> ProtocolResult {
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
                for (to, opt) in p2ps.into_vec().into_iter().enumerate() {
                    if let Some(p2p) = opt {
                        out_r1p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R1P2p { to },
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

            R2 => {
                let (state, bcast) = self.r3();
                self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R3Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r3state = Some(state);
                R3
            }
            R3 => {
                let (state, bcast) = self.r4();
                self.out_r4bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R4Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r4state = Some(state);
                R4
            }
            R4 => {
                let (state, bcast, p2ps) = self.r5();
                self.out_r5bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R5Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r5p2ps = Vec::with_capacity(self.participant_indices.len());
                for opt in p2ps {
                    if let Some(p2p) = opt {
                        out_r5p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R5P2p,
                            from: self.my_participant_index,
                            payload: bincode::serialize(&p2p)?,
                        })?));
                    } else {
                        out_r5p2ps.push(None);
                    }
                }
                self.out_r5p2ps = Some(out_r5p2ps);
                self.r5state = Some(state);
                R5
            }
            R5 => {
                let (state, bcast) = self.r6();
                self.out_r6bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R6Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r6state = Some(state);
                R6
            }
            R6 => {
                let (state, bcast) = self.r7();
                self.out_r7bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R7Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r7state = Some(state);
                R7
            }
            R7 => {
                self.final_output = Some(self.r8());
                Done
            }
            Done => return Err(From::from("already done")),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> ProtocolResult {
        // TODO match self.status
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        match msg_meta.msg_type {
            MsgType::R1Bcast => self
                .in_r1bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R1P2p { to } => self.in_all_r1p2ps[msg_meta.from]
                .insert(to, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R2P2p => self
                .in_r2p2ps
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R3Bcast => self
                .in_r3bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R4Bcast => self
                .in_r4bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R5Bcast => self
                .in_r5bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R5P2p => self
                .in_r5p2ps
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R6Bcast => self
                .in_r6bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R7Bcast => self
                .in_r7bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
        };
        Ok(())
    }

    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        match self.status {
            New => &None,
            R1 => &self.out_r1bcast,
            R2 => &None,
            R3 => &self.out_r3bcast,
            R4 => &self.out_r4bcast,
            R5 => &self.out_r5bcast,
            R6 => &self.out_r6bcast,
            R7 => &self.out_r7bcast,
            Done => &None,
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.status {
            New => &None,
            R1 => &self.out_r1p2ps,
            R2 => &self.out_r2p2ps,
            R3 => &None,
            R4 => &None,
            R5 => &self.out_r5p2ps,
            R6 => &None,
            R7 => &None,
            Done => &None,
        }
    }

    fn expecting_more_msgs_this_round(&self) -> bool {
        let me = self.my_participant_index;
        match self.status {
            New => false,
            R1 => {
                // TODO fix ugly code to deal with wasted entries for messages to myself
                if !self.in_r1bcasts.is_full_except(me) {
                    return true;
                }
                for (i, in_r1p2ps) in self.in_all_r1p2ps.iter().enumerate() {
                    if !in_r1p2ps.is_full_except(i) {
                        return true;
                    }
                }
                false
            }
            R2 => !self.in_r2p2ps.is_full_except(me),
            R3 => !self.in_r3bcasts.is_full_except(me),
            R4 => !self.in_r4bcasts.is_full_except(me),
            R5 => !self.in_r5bcasts.is_full_except(me) || !self.in_r5p2ps.is_full_except(me),
            R6 => !self.in_r6bcasts.is_full_except(me),
            R7 => !self.in_r7bcasts.is_full_except(me),
            Done => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.status, Done)
    }
}
