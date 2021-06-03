use super::{crimes::Crime, r3, r4, Keygen, MsgMeta, MsgType, Status::*};
use crate::{
    fillvec::FillVec,
    protocol::{IndexRange, MsgBytes, Protocol, ProtocolResult},
};

impl Protocol for Keygen {
    fn next_round(&mut self) -> ProtocolResult {
        if self.expecting_more_msgs_this_round() {
            return Err(From::from("can't prceed yet"));
        }

        // check if we have marked any party as unauthenticated
        if !self.unauth_parties.is_empty() {
            // create a vec of crimes with respect to unauthenticated parties
            let crimes = self
                .unauth_parties
                .vec_ref()
                .iter()
                .map(|&unauth| {
                    let mut my_crimes = vec![];
                    if let Some(victim) = unauth {
                        my_crimes.push(Crime::SpoofedMessage {
                            victim,
                            status: self.status.clone(),
                        });
                    }
                    my_crimes
                })
                .collect();
            self.update_state_fail(crimes);
            return Ok(());
        }

        // check if we have marked any deserialiation faults
        if !self.disrupting_parties.is_empty() {
            // create a vec of crimes with respect to deserialization faults
            let crimes = self
                .disrupting_parties
                .vec_ref()
                .iter()
                .map(|&failure| {
                    let mut my_crimes = vec![];
                    if failure.is_some() {
                        my_crimes.push(Crime::DisruptedMessage);
                    }
                    my_crimes
                })
                .collect();
            self.update_state_fail(crimes);
            return Ok(());
        }

        self.move_to_sad_path();

        // TODO refactor repeated code!
        match self.status {
            New => {
                let (state, bcast) = self.r1();
                self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R1Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r1state = Some(state);
                self.status = R1;
            }
            R1 => {
                let (state, bcast, p2ps) = self.r2();
                self.out_r2bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R2Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r2p2ps = Vec::with_capacity(self.share_count);
                for (to, opt) in p2ps.vec_ref().iter().enumerate() {
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

                self.in_all_r2p2ps[self.my_index] = p2ps;

                self.r2state = Some(state);
                self.status = R2;
            }

            R2 => match self.r3() {
                r3::Output::Success { state, out_bcast } => {
                    self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                        msg_type: MsgType::R3Bcast,
                        from: self.my_index,
                        payload: bincode::serialize(&out_bcast)?,
                    })?);
                    self.r3state = Some(state);
                    self.status = R3;
                }
                r3::Output::Fail { criminals } => self.update_state_fail(criminals),
                r3::Output::FailVss { out_bcast } => {
                    self.out_r3bcast_fail = Some(bincode::serialize(&MsgMeta {
                        msg_type: MsgType::R3FailBcast,
                        from: self.my_index,
                        payload: bincode::serialize(&out_bcast)?,
                    })?);
                    self.status = R3Fail;
                }
            },
            R3 => match self.r4() {
                r4::Output::Success { key_share } => {
                    self.final_output = Some(Ok(key_share));
                    self.status = Done;
                }
                r4::Output::Fail { criminals } => self.update_state_fail(criminals),
            },
            R3Fail => self.update_state_fail(self.r4_fail()),
            Done => return Err(From::from("already done")),
            Fail => return Err(From::from("already failed")),
        };
        Ok(())
    }

    fn set_msg_in(&mut self, msg: &[u8], from_index_range: &IndexRange) -> ProtocolResult {
        let res = self.set_msg_in_inner(&msg, &from_index_range);
        if res.is_err() {
            self.disrupting_parties
                .overwrite(from_index_range.first, true);
        }
        Ok(())
    }

    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        match self.status {
            New => &None,
            R1 => &self.out_r1bcast,
            R2 => &self.out_r2bcast,
            R3 => &self.out_r3bcast,
            R3Fail => &self.out_r3bcast_fail,
            Done | Fail => &None,
        }
    }

    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        match self.status {
            New => &None,
            R1 => &None,
            R2 => &self.out_r2p2ps,
            R3 => &None,
            R3Fail => &None,
            Done | Fail => &None,
        }
    }

    fn expecting_more_msgs_this_round(&self) -> bool {
        match self.status {
            New => false,
            R1 => !self.in_r1bcasts.is_full(),
            R2 => {
                if !self.in_r2bcasts.is_full() {
                    return true;
                }
                for (i, in_r2p2ps) in self.in_all_r2p2ps.iter().enumerate() {
                    if !in_r2p2ps.is_full_except(i) {
                        return true;
                    }
                }
                false
            }
            R3 | R3Fail => {
                for i in 0..self.share_count {
                    if self.in_r3bcasts.is_none(i) && self.in_r3bcasts_fail.is_none(i) {
                        return true;
                    }
                }
                false
            }
            Done | Fail => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.status, Done | Fail)
    }
}

impl Keygen {
    fn update_state_fail(&mut self, criminals: Vec<Vec<Crime>>) {
        self.final_output = Some(Err(criminals));
        self.status = Fail;
    }
    fn move_to_sad_path(&mut self) {
        match self.status {
            R3 => {
                if self.in_r3bcasts_fail.some_count() > 0 {
                    self.status = R3Fail;
                }
            }
            // do not use catch-all pattern `_ => (),`
            // instead, list all variants explicity
            // because otherwise you'll forget to update this match statement when you add a variant
            R1 | R2 | R3Fail | New | Done | Fail => {}
        }
    }

    fn set_msg_in_inner(&mut self, msg: &[u8], from_index_range: &IndexRange) -> ProtocolResult {
        // TODO match self.state
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        if !from_index_range.includes(msg_meta.from) {
            self.unauth_parties
                .overwrite(from_index_range.first, msg_meta.from);
        }
        match msg_meta.msg_type {
            MsgType::R1Bcast => self
                .in_r1bcasts
                .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?),
            MsgType::R2Bcast => self
                .in_r2bcasts
                .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?),
            MsgType::R2P2p { to } => self.in_all_r2p2ps[msg_meta.from]
                .overwrite(to, bincode::deserialize(&msg_meta.payload)?),
            MsgType::R3Bcast => self
                .in_r3bcasts
                .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?),
            MsgType::R3FailBcast => self
                .in_r3bcasts_fail
                .overwrite(msg_meta.from, bincode::deserialize(&msg_meta.payload)?),
        };
        Ok(())
    }

    // return timeout crimes derived by messages that have not been received at the current round
    pub fn waiting_on(&self) -> Vec<Vec<Crime>> {
        // vec with crimes starts empty; return it as is in trivial cases
        let mut crimes = vec![vec![]; self.in_r1bcasts.vec_ref().len()];
        match self.status {
            New => crimes,
            R1 => Self::crimes_from_fillvec(&self.in_r1bcasts, MsgType::R1Bcast),
            R2 => {
                // find bcast crimes
                crimes = Self::crimes_from_fillvec(&self.in_r2bcasts, MsgType::R2Bcast);
                // get bcast crimes
                self.crimes_from_vec_fillvec(&self.in_all_r2p2ps)
                    .into_iter()
                    .enumerate()
                    // accumulate all party's bcast crimes with all his p2p crimes
                    .for_each(|(i, p2p_crimes)| crimes[i].extend(p2p_crimes));
                crimes
            }
            R3 => Self::crimes_from_fillvec(&self.in_r3bcasts, MsgType::R3Bcast),
            R3Fail => Self::crimes_from_fillvec(&self.in_r3bcasts_fail, MsgType::R3FailBcast),
            Done | Fail => crimes,
        }
    }

    // create crimes out the missing entires in a fillvec; see test_waiting_on_bcast()
    // - fillvec [Some(), Some(), Some()] returns [[], [], []]
    // - fillvec [Some(), Some(),  None ] returns [[], [], [Crime::Staller{msg_type: RXBcast}]]
    fn crimes_from_fillvec<T>(fillvec: &FillVec<T>, msg_type: MsgType) -> Vec<Vec<Crime>> {
        if fillvec.is_full() {
            return vec![vec![]; fillvec.vec_ref().len()];
        }
        fillvec
            .vec_ref()
            .iter()
            .map(|element| {
                // if we have a msg from the ith party, he is not a staller
                if element.is_some() {
                    return vec![];
                }
                // else add a crime in that index
                vec![Crime::StalledMessage {
                    msg_type: msg_type.clone(),
                }]
            })
            .collect()
    }

    // get the p2p message type that corresponds to this state
    fn current_p2p_msg(&self, to: usize) -> Option<MsgType> {
        match self.status {
            R2 => Some(MsgType::R2P2p { to }),
            // do not use catch-all pattern `_ => None,`
            // instead, list all variants explicity
            // because otherwise you'll forget to update this match statement when you add a variant
            R1 | R3 | R3Fail | New | Done | Fail => None,
        }
    }

    // create crimes out of the missing entries in a vec of fillvecs; see test_waiting_on_p2p()
    // - vec<fillvec> [[  --  , Some(), Some()], <- party 0 list
    //                 [Some(),   --  , Some()], <- party 1 list
    //                 [Some(), Some(),   --  ]] <- party 2 list
    //        returns [[], [], []]
    // - vec<fillvec> [[  --  , Some(), Some()], <- party 0 list;
    //                 [ None ,   --  , Some()], <- party 1 list; p0 didn't recv p2p from p1
    //                 [Some(), Some(),   --  ]] <- party 2 list;
    //        returns [[],
    //                 [Crime::Staller{msg_type: RXP2p{to: 0}}]
    //                 []]
    fn crimes_from_vec_fillvec<T>(&self, vec_fillvec: &[FillVec<T>]) -> Vec<Vec<Crime>> {
        let mut crimes = vec![vec![]; vec_fillvec.len()];
        for (criminal, p2ps) in vec_fillvec.iter().enumerate() {
            for (victim, p2p) in p2ps.vec_ref().iter().enumerate() {
                if p2p.is_none() && victim != criminal {
                    crimes[criminal].push(Crime::StalledMessage {
                        msg_type: self.current_p2p_msg(victim).unwrap(),
                    });
                }
            }
        }
        crimes
    }
}
