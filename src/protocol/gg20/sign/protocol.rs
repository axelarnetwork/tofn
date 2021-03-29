use super::{Status::*, *};
use crate::protocol::{MsgBytes, Protocol, ProtocolResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R1P2p { to: usize },
    R2P2p { to: usize },
    R2FailBcast,
    R3Bcast,
    R4Bcast,
    R5Bcast,
    R5P2p { to: usize },
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
        self.move_to_sad_path();

        // TODO refactor repeated code!
        match self.status {
            New => {
                let (state, bcast, p2ps) = self.r1();
                self.update_state_r1(state, bcast, p2ps)?;
            }

            R1 => match self.r2() {
                r2::Output::Success { state, out_p2ps } => {
                    let mut out_p2ps_serialized =
                        Vec::with_capacity(self.participant_indices.len());
                    for (to, opt) in out_p2ps.into_vec().into_iter().enumerate() {
                        if let Some(p2p) = opt {
                            out_p2ps_serialized.push(Some(bincode::serialize(&MsgMeta {
                                msg_type: MsgType::R2P2p { to },
                                from: self.my_participant_index,
                                payload: bincode::serialize(&p2p)?,
                            })?));
                        } else {
                            out_p2ps_serialized.push(None);
                        }
                    }
                    self.out_r2p2ps = Some(out_p2ps_serialized);
                    self.r2state = Some(state);
                    self.status = R2;
                }
                r2::Output::Fail { out_bcast } => {
                    // serialize outgoing bcast
                    self.out_r2bcast_fail_serialized = Some(bincode::serialize(&MsgMeta {
                        msg_type: MsgType::R2FailBcast,
                        from: self.my_participant_index,
                        payload: bincode::serialize(&out_bcast)?,
                    })?);

                    // self delivery
                    self.in_r2bcasts_fail
                        .insert(self.my_participant_index, out_bcast)?;

                    self.status = R2Fail;
                }
            },

            R2 => {
                let (state, bcast) = self.r3();
                self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R3Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r3state = Some(state);
                self.status = R3;
            }
            R2Fail => {
                self.final_output = Some(Err(self.r3fail()));
                self.status = Fail;
            }
            R3 => {
                let (state, bcast) = self.r4();
                self.out_r4bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R4Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r4state = Some(state);
                self.status = R4;
            }
            R4 => {
                let (state, bcast, p2ps) = self.r5();
                self.out_r5bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R5Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r5p2ps = Vec::with_capacity(self.participant_indices.len());
                for (to, opt) in p2ps.into_vec().into_iter().enumerate() {
                    if let Some(p2p) = opt {
                        out_r5p2ps.push(Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R5P2p { to },
                            from: self.my_participant_index,
                            payload: bincode::serialize(&p2p)?,
                        })?));
                    } else {
                        out_r5p2ps.push(None);
                    }
                }
                self.out_r5p2ps = Some(out_r5p2ps);
                self.r5state = Some(state);
                self.status = R5;
            }
            R5 => {
                let (state, bcast) = self.r6();
                self.out_r6bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R6Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r6state = Some(state);
                self.status = R6;
            }
            R6 => {
                let (state, bcast) = self.r7();
                self.out_r7bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R7Bcast,
                    from: self.my_participant_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r7state = Some(state);
                self.status = R7;
            }
            R7 => {
                self.final_output = Some(Ok(self.r8()));
                self.status = Done;
            }
            Done => return Err(From::from("already done")),
            Fail => return Err(From::from("already failed")),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> ProtocolResult {
        // TODO match self.status
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        match msg_meta.msg_type {
            MsgType::R1Bcast => {
                if !self.in_r1bcasts.is_none(msg_meta.from) {
                    println!(
                        "WARN: participant {} overwrite existing R1Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r1bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R1P2p { to } => {
                let r1_p2ps = &mut self.in_all_r1p2ps[msg_meta.from];
                if !r1_p2ps.is_none(to) {
                    println!(
                        "WARN: participant {} overwrite existing R1P2p msg from {} to {}",
                        self.my_participant_index, msg_meta.from, to
                    );
                }
                r1_p2ps.overwrite(to, bincode::deserialize(&msg_meta.payload)?);
            }
            MsgType::R2P2p { to } => self.in_all_r2p2ps[msg_meta.from]
                .insert(to, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R2FailBcast => {
                if !self.in_r2bcasts_fail.is_none(msg_meta.from) {
                    println!(
                        "WARN: participant {} overwrite existing R2FailBcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r2bcasts_fail
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R3Bcast => self
                .in_r3bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R4Bcast => self
                .in_r4bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R5Bcast => self
                .in_r5bcasts
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgType::R5P2p { to } => self.in_all_r5p2ps[msg_meta.from]
                .insert(to, bincode::deserialize(&msg_meta.payload)?)?,
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
            R2Fail => &self.out_r2bcast_fail_serialized,
            R3 => &self.out_r3bcast,
            R4 => &self.out_r4bcast,
            R5 => &self.out_r5bcast,
            R6 => &self.out_r6bcast,
            R7 => &self.out_r7bcast,
            Done => &None,
            Fail => &None,
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.status {
            New => &None,
            R1 => &self.out_r1p2ps,
            R2 => &self.out_r2p2ps,
            R2Fail => &None,
            R3 => &None,
            R4 => &None,
            R5 => &self.out_r5p2ps,
            R6 => &None,
            R7 => &None,
            Done => &None,
            Fail => &None,
        }
    }

    fn expecting_more_msgs_this_round(&self) -> bool {
        let me = self.my_participant_index;

        // TODO account for sad path messages
        // need to receive one message per party (happy OR sad)

        match self.status {
            New => false,
            R1 => {
                // TODO fix ugly code to deal with wasted entries for messages to myself
                if !self.in_r1bcasts.is_full_except(me) {
                    return true;
                }
                for (i, in_r1p2ps) in self.in_all_r1p2ps.iter().enumerate() {
                    if i == me {
                        continue;
                    }
                    if !in_r1p2ps.is_full_except(i) {
                        return true;
                    }
                }
                false
            }
            R2 | R2Fail => {
                for i in 0..self.participant_indices.len() {
                    if i == me {
                        continue;
                    }
                    if !self.in_all_r2p2ps[i].is_full_except(i) && self.in_r2bcasts_fail.is_none(i)
                    {
                        return true;
                    }
                }
                false
            }
            R3 => !self.in_r3bcasts.is_full_except(me),
            R4 => !self.in_r4bcasts.is_full_except(me),
            R5 => {
                // TODO fix ugly code to deal with wasted entries for messages to myself
                if !self.in_r5bcasts.is_full_except(me) {
                    return true;
                }
                for (i, in_r5p2ps) in self.in_all_r5p2ps.iter().enumerate() {
                    if i == me {
                        continue;
                    }
                    if !in_r5p2ps.is_full_except(i) {
                        return true;
                    }
                }
                false
            }
            R6 => !self.in_r6bcasts.is_full_except(me),
            R7 => !self.in_r7bcasts.is_full_except(me),
            Done => false,
            Fail => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.status, Done | Fail)
    }
}

// TODO these methods should be private - break abstraction for tests only
impl Sign {
    pub(super) fn move_to_sad_path(&mut self) {
        if let R2 = self.status {
            // if I've received any r2 bcast fails then switch to R2Fail status
            if self.in_r2bcasts_fail.some_count() > 0 {
                self.status = R2Fail;
            }
        }
    }

    pub(super) fn update_state_r1(
        &mut self,
        state: r1::State,
        bcast: r1::Bcast,
        p2ps: FillVec<r1::P2p>,
    ) -> ProtocolResult {
        // serialize outgoing bcast
        self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R1Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);

        // serialize outgoing p2ps
        let mut out_r1p2ps = Vec::with_capacity(self.participant_indices.len());
        for (to, opt) in p2ps.vec_ref().iter().enumerate() {
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

        // self delivery
        self.in_r1bcasts.insert(self.my_participant_index, bcast)?;
        self.in_all_r1p2ps[self.my_participant_index] = p2ps;

        self.r1state = Some(state);
        self.status = R1;
        Ok(())
    }
}
