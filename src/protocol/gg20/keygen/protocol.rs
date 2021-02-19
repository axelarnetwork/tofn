use super::{
    stateless::{r1, r2, r3, r4, R1State, R2State, R3State},
    Keygen,
    State::*,
    Status,
};
use crate::{
    fillvec::FillVec,
    protocol::{MsgBytes, Protocol, ProtocolResult},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p,
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
        self.state = match &self.state {
            New => {
                let (state, bcast) = self.r1();
                self.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R1Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r1state = Some(state);

                // TODO transitory
                self.status = Status::R1;
                R1(R1State {
                    share_count: self.share_count,
                    threshold: self.threshold,
                    my_index: self.my_index,
                    my_ecdsa_secret_summand: self.r1state.as_ref().unwrap().my_ecdsa_secret_summand,
                    my_ecdsa_public_summand: self.r1state.as_ref().unwrap().my_ecdsa_public_summand,
                    my_dk: self.r1state.as_ref().unwrap().my_dk.clone(),
                    my_ek: self.r1state.as_ref().unwrap().my_ek.clone(),
                    my_commit: bcast.commit,
                    my_reveal: self.r1state.as_ref().unwrap().my_reveal.clone(),
                })
            }

            R1(state) => {
                let (state, bcast, p2ps) = self.r2();
                self.out_r2bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R2Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                let mut out_r2p2ps = Vec::with_capacity(self.share_count);
                for opt in p2ps {
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
                self.r2state = Some(state);

                // TODO transitory
                self.status = Status::R2;
                R2(R2State {
                    share_count: self.share_count,
                    threshold: self.threshold,
                    my_index: self.my_index,
                    my_dk: self.r1state.as_ref().as_ref().unwrap().my_dk.clone(),
                    my_ek: self.r1state.as_ref().as_ref().unwrap().my_ek.clone(),
                    my_share_of_my_ecdsa_secret_summand: self
                        .r2state
                        .as_ref()
                        .unwrap()
                        .my_share_of_my_ecdsa_secret_summand,
                    my_ecdsa_public_summand: self.r1state.as_ref().unwrap().my_ecdsa_public_summand,
                    all_commits: self.r2state.as_ref().unwrap().all_commits.clone(),
                    all_eks: self.r2state.as_ref().unwrap().all_eks.clone(),
                })
            }

            R2(state) => {
                let (state, bcast) = self.r3();
                self.out_r3bcast = Some(bincode::serialize(&MsgMeta {
                    msg_type: MsgType::R3Bcast,
                    from: self.my_index,
                    payload: bincode::serialize(&bcast)?,
                })?);
                self.r3state = Some(state);

                // TODO transitory
                self.status = Status::R3;
                R3(R3State {
                    share_count: self.share_count,
                    threshold: self.threshold,
                    my_index: self.my_index,
                    my_dk: self.r1state.as_ref().as_ref().unwrap().my_dk.clone(),
                    my_ek: self.r1state.as_ref().as_ref().unwrap().my_ek.clone(),
                    ecdsa_public_key: self.r3state.as_ref().unwrap().ecdsa_public_key,
                    my_ecdsa_secret_key_share: self
                        .r3state
                        .as_ref()
                        .unwrap()
                        .my_ecdsa_secret_key_share,
                    all_eks: self.r2state.as_ref().unwrap().all_eks.clone(),
                })
            }

            R3(state) => {
                self.final_output = Some(r4::execute(state, self.in_r3bcasts.vec_ref()));
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

    fn expecting_more_msgs_this_round(&self) -> bool {
        let i = self.my_index;
        match self.state {
            New => false,
            R1(_) => !self.in_r1bcasts.is_full_except(i),
            R2(_) => !self.in_r2bcasts.is_full_except(i) || !self.in_r2p2ps.is_full_except(i),
            R3(_) => !self.in_r3bcasts.is_full_except(i),
            Done => false,
        }
    }

    fn done(&self) -> bool {
        matches!(self.state, Done)
    }
}
