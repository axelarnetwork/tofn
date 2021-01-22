use crate::{
    fillvec::FillVec,
    protocol::gg20::keygen::stateless::*,
    protocol2::{MsgBytes, Protocol2},
};
use serde::{Deserialize, Serialize};

enum State {
    New,
    R1(R1State),
    R2(R2State),
    R3(R3State),
    Done,
}
use State::*;

#[derive(Serialize, Deserialize)]
enum MsgTypes {
    R1Bcast,
    R2Bcast,
    R2P2p,
    R3Bcast,
}
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgTypes,
    from: usize,
    payload: MsgBytes,
}
pub struct KeygenProtocol {
    state: State,

    // protocol-wide data
    share_count: usize,
    threshold: usize,
    my_index: usize,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    out_r1bcast: Option<MsgBytes>,
    out_r2bcast: Option<MsgBytes>,
    out_r2p2p: Vec<Option<MsgBytes>>,
    out_r3bcast: Option<MsgBytes>,
    final_output: Option<MsgBytes>, // TODO why serialize result?

    in_r1bcast: FillVec<R1Bcast>,
    in_r2bcast: FillVec<R2Bcast>,
    in_r2p2p: FillVec<R2P2p>,
    in_r3bcast: FillVec<R3Bcast>,
}

impl KeygenProtocol {
    pub fn new(share_count: usize, threshold: usize, my_index: usize) -> Self {
        Self {
            state: New,
            share_count,
            threshold,
            my_index,
            out_r1bcast: None,
            out_r2bcast: None,
            out_r2p2p: FillVec::new_vec_none(share_count),
            out_r3bcast: None,
            final_output: None,
            in_r1bcast: FillVec::with_capacity(share_count),
            in_r2bcast: FillVec::with_capacity(share_count),
            in_r2p2p: FillVec::with_capacity(share_count),
            in_r3bcast: FillVec::with_capacity(share_count),
        }
    }
}

impl Protocol2 for KeygenProtocol {
    fn next(&mut self) {
        // TODO return early if can_proceed() == false?
        self.state = match self.state {
            New => {
                let (r1state, out_r1bcast) = r1::start();
                self.out_r1bcast = Some(
                    bincode::serialize(&out_r1bcast).expect("failure to serialize out_r1bcast"),
                );
                R1(r1state)
            }
            _ => todo!(),
        }
    }

    fn set_msg_in(&mut self, msg: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // TODO match self.state?
        let msg_meta: MsgMeta = bincode::deserialize(msg)?;
        match msg_meta.msg_type {
            MsgTypes::R1Bcast => self
                .in_r1bcast
                .insert(msg_meta.from, bincode::deserialize(&msg_meta.payload)?)?,
            MsgTypes::R2Bcast => {}
            MsgTypes::R2P2p => {}
            MsgTypes::R3Bcast => {}
        }
        todo!()
    }

    fn get_bcast_out(&self) -> Option<MsgBytes> {
        todo!()
    }

    fn get_p2p_out(&self) -> Vec<Option<MsgBytes>> {
        todo!()
    }

    fn can_proceed(&self) -> bool {
        match self.state {
            New => true,
            _ => todo!(),
        }
    }

    fn done(&self) -> bool {
        todo!()
    }

    fn get_result(&self) -> Option<MsgBytes> {
        todo!()
    }
}
