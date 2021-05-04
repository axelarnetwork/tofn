use super::{crimes::Crime, Status::*, *};
use crate::protocol::{MsgBytes, Protocol, ProtocolResult};
use serde::{Deserialize, Serialize};

use tracing::debug;

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R1P2p { to: usize },
    R2P2p { to: usize },
    R2FailBcast,
    R3Bcast,
    R3FailBcast,
    R4Bcast,
    R5Bcast,
    R5P2p { to: usize },
    R6Bcast,
    R6FailBcast,
    R6FailBcastRandomizer,
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
                    self.update_state_r2(state, out_p2ps)?;
                }
                r2::Output::Fail { out_bcast } => {
                    self.update_state_r2fail(out_bcast)?;
                }
            },

            R2 => match self.r3() {
                r3::Output::Success { state, out_bcast } => {
                    self.update_state_r3(state, out_bcast)?;
                }
                r3::Output::Fail { out_bcast } => {
                    self.update_state_r3fail(out_bcast)?;
                }
            },
            R2Fail => self.update_state_fail(self.r3_fail()),
            R3 => match self.r4() {
                r4::Output::Success { state, out_bcast } => {
                    self.update_state_r4(state, out_bcast)?;
                }
                r4::Output::Fail { criminals } => {
                    self.update_state_fail(criminals);
                }
            },
            R3Fail => self.update_state_fail(self.r4_fail()),
            R4 => match self.r5() {
                r5::Output::Success {
                    state,
                    out_bcast,
                    out_p2ps,
                } => {
                    self.update_state_r5(state, out_bcast, out_p2ps)?;
                }
                r5::Output::Fail { criminals } => {
                    self.update_state_fail(criminals);
                }
            },
            R5 => match self.r6() {
                r6::Output::Success { state, out_bcast } => {
                    self.update_state_r6(state, out_bcast)?;
                }
                r6::Output::FailRangeProofWc { out_bcast } => {
                    self.update_state_r6fail(out_bcast)?;
                }
                r6::Output::FailRandomizer { out_bcast } => {
                    self.update_state_r6fail_randomizer(out_bcast)?;
                }
            },
            R6 => match self.r7() {
                r7::Output::Success { state, out_bcast } => {
                    self.update_state_r7(state, out_bcast)?;
                }
                r7::Output::Fail { criminals } => {
                    self.update_state_fail(criminals);
                }
            },
            R6Fail => self.update_state_fail(self.r7_fail()),
            R6FailRandomizer => self.update_state_fail(self.r7_fail_randomizer()),
            R7 => match self.r8() {
                r8::Output::Success { sig } => {
                    // self.final_output = Some(Output::Ok(sig.as_bytes().to_vec()));
                    self.final_output = Some(Ok(sig.as_bytes().to_vec()));
                    self.status = Done;
                }
                r8::Output::Fail { criminals } => self.update_state_fail(criminals),
            },
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
                    debug!(
                        "participant {} overwrite existing R1Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r1bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R1P2p { to } => {
                let r1_p2ps = &mut self.in_all_r1p2ps[msg_meta.from];
                if !r1_p2ps.is_none(to) {
                    debug!(
                        "participant {} overwrite existing R1P2p msg from {} to {}",
                        self.my_participant_index, msg_meta.from, to
                    );
                }
                r1_p2ps.overwrite(to, bincode::deserialize(&msg_meta.payload)?);
            }
            MsgType::R2P2p { to } => {
                let r2_p2ps = &mut self.in_all_r2p2ps[msg_meta.from];
                if !r2_p2ps.is_none(to) {
                    debug!(
                        "participant {} overwrite existing R2P2p msg from {} to {}",
                        self.my_participant_index, msg_meta.from, to
                    );
                }
                r2_p2ps.overwrite(to, bincode::deserialize(&msg_meta.payload)?);
            }
            MsgType::R2FailBcast => {
                if !self.in_r2bcasts_fail.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R2FailBcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r2bcasts_fail
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R3Bcast => {
                if !self.in_r3bcasts.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R3Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r3bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R3FailBcast => {
                if !self.in_r3bcasts_fail.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R3FailBcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r3bcasts_fail
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R4Bcast => {
                if !self.in_r4bcasts.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R4Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r4bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R5Bcast => {
                if !self.in_r5bcasts.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R5Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r5bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R5P2p { to } => {
                let r5_p2ps = &mut self.in_all_r5p2ps[msg_meta.from];
                if !r5_p2ps.is_none(to) {
                    debug!(
                        "participant {} overwrite existing R5P2p msg from {} to {}",
                        self.my_participant_index, msg_meta.from, to
                    );
                }
                r5_p2ps.overwrite(to, bincode::deserialize(&msg_meta.payload)?);
            }
            MsgType::R6Bcast => {
                if !self.in_r6bcasts.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R6Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r6bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R6FailBcast => {
                if !self.in_r6bcasts_fail.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R6FailBcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r6bcasts_fail
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R6FailBcastRandomizer => {
                if !self.in_r6bcasts_fail_randomizer.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R6FailBcastRandomizer msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r6bcasts_fail_randomizer
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
            MsgType::R7Bcast => {
                if !self.in_r7bcasts.is_none(msg_meta.from) {
                    debug!(
                        "participant {} overwrite existing R7Bcast msg from {}",
                        self.my_participant_index, msg_meta.from
                    );
                }
                self.in_r7bcasts
                    .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)
            }
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
            R3Fail => &self.out_r3bcast_fail_serialized,
            R4 => &self.out_r4bcast,
            R5 => &self.out_r5bcast,
            R6 => &self.out_r6bcast,
            R6Fail => &self.out_r6bcast_fail_serialized,
            R6FailRandomizer => &self.out_r6bcast_fail_randomizer_serialized,
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
            R3Fail => &None,
            R4 => &None,
            R5 => &self.out_r5p2ps,
            R6 => &None,
            R6Fail => &None,
            R6FailRandomizer => &None,
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
            R3 | R3Fail => {
                for i in 0..self.participant_indices.len() {
                    if i == me {
                        continue;
                    }
                    if self.in_r3bcasts.is_none(i) && self.in_r3bcasts_fail.is_none(i) {
                        return true;
                    }
                }
                false
            }
            R4 => {
                if !self.in_r4bcasts.is_full_except(me) {
                    return true;
                }
                false
            }
            R5 => {
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
            R6 | R6Fail | R6FailRandomizer => {
                for i in 0..self.participant_indices.len() {
                    if i == me {
                        continue;
                    }
                    if self.in_r6bcasts.is_none(i)
                        && self.in_r6bcasts_fail.is_none(i)
                        && self.in_r6bcasts_fail_randomizer.is_none(i)
                    {
                        return true;
                    }
                }
                false
            }
            R7 => {
                if !self.in_r7bcasts.is_full_except(me) {
                    return true;
                }
                false
            }
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
        match self.status {
            R2 => {
                if self.in_r2bcasts_fail.some_count() > 0 {
                    self.status = R2Fail;
                }
            }
            R3 => {
                if self.in_r3bcasts_fail.some_count() > 0 {
                    self.status = R3Fail;
                }
            }
            R6 => {
                // prioritize R6Fail over R6FailRandomizer
                if self.in_r6bcasts_fail.some_count() > 0 {
                    self.status = R6Fail;
                }
            }
            // do not use catch-all pattern `_ => (),`
            // instead, list all variants explicity
            // because otherwise you'll forget to update this match statement when you add a variant
            R1 | R2Fail | R3Fail | R4 | R5 | R6Fail | R6FailRandomizer | R7 | New | Done | Fail => {
                ()
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

    pub(super) fn update_state_r2(
        &mut self,
        state: r2::State,
        out_p2ps: FillVec<r2::P2p>,
    ) -> ProtocolResult {
        let mut out_p2ps_serialized = Vec::with_capacity(self.participant_indices.len());
        for (to, opt) in out_p2ps.vec_ref().iter().enumerate() {
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
        self.in_all_r2p2ps[self.my_participant_index] = out_p2ps; // self delivery
        self.r2state = Some(state);
        self.status = R2;
        Ok(())
    }

    pub(super) fn update_state_r2fail(&mut self, bcast: r2::FailBcast) -> ProtocolResult {
        self.out_r2bcast_fail_serialized = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R2FailBcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);
        self.in_r2bcasts_fail
            .insert(self.my_participant_index, bcast)?; // self delivery
        self.status = R2Fail;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2
    pub(super) fn update_state_r3(
        &mut self,
        state: r3::State,
        out_bcast: r3::Bcast,
    ) -> ProtocolResult {
        self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R3Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&out_bcast)?,
        })?);
        self.in_r3bcasts
            .insert(self.my_participant_index, out_bcast)?; // self delivery
        self.r3state = Some(state);
        self.status = R3;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2fail
    pub(super) fn update_state_r3fail(&mut self, bcast: r3::FailBcast) -> ProtocolResult {
        // serialize outgoing bcast
        self.out_r3bcast_fail_serialized = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R3FailBcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);
        self.in_r3bcasts_fail
            .insert(self.my_participant_index, bcast)?; // self delivery
        self.status = R3Fail;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2
    pub(super) fn update_state_r4(
        &mut self,
        state: r4::State,
        out_bcast: r4::Bcast,
    ) -> ProtocolResult {
        self.out_r4bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R4Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&out_bcast)?,
        })?);
        self.in_r4bcasts
            .insert(self.my_participant_index, out_bcast)?; // self delivery
        self.r4state = Some(state);
        self.status = R4;
        Ok(())
    }

    // TODO refactor copied code from update_state_r1
    pub(super) fn update_state_r5(
        &mut self,
        state: r5::State,
        bcast: r5::Bcast,
        p2ps: FillVec<r5::P2p>,
    ) -> ProtocolResult {
        // serialize outgoing bcast
        self.out_r5bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R5Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);

        // serialize outgoing p2ps
        let mut out_r5p2ps = Vec::with_capacity(self.participant_indices.len());
        for (to, opt) in p2ps.vec_ref().iter().enumerate() {
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

        // self delivery
        self.in_r5bcasts.insert(self.my_participant_index, bcast)?;
        self.in_all_r5p2ps[self.my_participant_index] = p2ps;

        self.r5state = Some(state);
        self.status = R5;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2
    pub(super) fn update_state_r6(
        &mut self,
        state: r6::State,
        out_bcast: r6::Bcast,
    ) -> ProtocolResult {
        self.out_r6bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R6Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&out_bcast)?,
        })?);
        self.in_r6bcasts
            .insert(self.my_participant_index, out_bcast)?; // self delivery
        self.r6state = Some(state);
        self.status = R6;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2fail
    pub(super) fn update_state_r6fail(&mut self, bcast: r6::BcastCulprits) -> ProtocolResult {
        self.out_r6bcast_fail_serialized = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R6FailBcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);
        self.in_r6bcasts_fail
            .insert(self.my_participant_index, bcast)?; // self delivery
        self.status = R6Fail;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2fail
    pub(super) fn update_state_r6fail_randomizer(
        &mut self,
        bcast: r6::BcastRandomizer,
    ) -> ProtocolResult {
        self.out_r6bcast_fail_randomizer_serialized = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R6FailBcastRandomizer,
            from: self.my_participant_index,
            payload: bincode::serialize(&bcast)?,
        })?);
        self.in_r6bcasts_fail_randomizer
            .insert(self.my_participant_index, bcast)?; // self delivery
        self.status = R6FailRandomizer;
        Ok(())
    }

    // TODO refactor copied code from update_state_r2
    pub(super) fn update_state_r7(
        &mut self,
        state: r7::State,
        out_bcast: r7::Bcast,
    ) -> ProtocolResult {
        self.out_r7bcast = Some(bincode::serialize(&MsgMeta {
            msg_type: MsgType::R7Bcast,
            from: self.my_participant_index,
            payload: bincode::serialize(&out_bcast)?,
        })?);
        self.in_r7bcasts
            .insert(self.my_participant_index, out_bcast)?; // self delivery
        self.r7state = Some(state);
        self.status = R7;
        Ok(())
    }

    pub(super) fn update_state_fail(&mut self, criminals: Vec<Vec<Crime>>) {
        // self.final_output = Some(Output::Err(to_criminals(&criminals)));
        self.final_output = Some(Err(criminals));
        self.status = Fail;
    }
}
