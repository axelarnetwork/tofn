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
        todo!()
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> Result {
        todo!()
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
        todo!()
    }
}
