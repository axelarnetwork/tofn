use super::{crimes::Crime, r3, Keygen, Status::*};
use crate::protocol::{
    gg20::keygen::malicious::Behaviour, IndexRange, MsgBytes, Protocol, ProtocolResult,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p { to: usize },
    R3Bcast,
    R3FailBcast,
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

        // check if we have marked any party as unauthenticated
        if self.unauth_parties.iter().any(|unauth| unauth.is_some()) {
            let crimes = self
                .unauth_parties
                .iter()
                .map(|&unauth| {
                    let mut my_crimes = vec![];
                    if let Some(victim) = unauth {
                        my_crimes.push(Crime::SpoofedMessage { victim });
                    }
                    my_crimes
                })
                .collect();
            self.update_state_fail(crimes);
            return Ok(());
        }

        // handle unathenticated case
        #[cfg(feature = "malicious")]
        if let Behaviour::UnauthenticatedSender { victim: v } = self.behaviour {
            self.my_index = v;
            // self.next_round()
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
                self.in_r1bcasts.insert(self.my_index, bcast)?; // self-delivery
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

                // self delivery
                self.in_r2bcasts.insert(self.my_index, bcast)?;
                self.in_all_r2p2ps[self.my_index] = p2ps;

                self.r2state = Some(state);
                self.status = R2;
            }

            R2 => {
                match self.r3() {
                    r3::Output::Success { state, out_bcast } => {
                        self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R3Bcast,
                            from: self.my_index,
                            payload: bincode::serialize(&out_bcast)?,
                        })?);
                        self.r3state = Some(state);
                        self.in_r3bcasts.insert(self.my_index, out_bcast)?; // self-delivery
                        self.status = R3;
                    }
                    r3::Output::Fail { criminals } => self.update_state_fail(criminals),
                    r3::Output::FailVss { out_bcast } => {
                        self.out_r3bcast_fail = Some(bincode::serialize(&MsgMeta {
                            msg_type: MsgType::R3FailBcast,
                            from: self.my_index,
                            payload: bincode::serialize(&out_bcast)?,
                        })?);
                        self.in_r3bcasts_fail.insert(self.my_index, out_bcast)?; // self delivery
                        self.status = R3Fail;
                    }
                }
            }
            R3 => {
                self.final_output = Some(Ok(self.r4()));
                self.status = Done;
            }
            R3Fail => self.update_state_fail(self.r4_fail()),
            Done => return Err(From::from("already done")),
            Fail => return Err(From::from("already failed")),
        };
        Ok(())
    }

    // TODO check for unauthenticated messages as in sign
    fn set_msg_in(&mut self, msg: &[u8], from_index_range: &IndexRange) -> ProtocolResult {
        // TODO match self.state
        // TODO refactor repeated code
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        if !from_index_range.includes(msg_meta.from) {
            self.unauth_parties[from_index_range.first] = Some(msg_meta.from);
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
            R3 | R3Fail => {
                for i in 0..self.share_count {
                    if i == me {
                        continue;
                    }
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
}
