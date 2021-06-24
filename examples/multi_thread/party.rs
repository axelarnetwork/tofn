use super::Broadcaster;
use std::sync::mpsc::Receiver;

use tofn::refactor::protocol::protocol::Protocol::{self, *};

#[derive(Clone)]
pub enum Message {
    Bcast {
        from: usize,
        bytes: Vec<u8>,
    },
    P2p {
        from: usize,
        to: usize,
        bytes: Vec<u8>,
    },
}

pub fn execute_protocol<F>(
    mut party: Protocol<F>,
    input: Receiver<Message>,
    broadcaster: Broadcaster<Message>,
) -> F {
    while let NotDone(mut round) = party {
        // send outgoing messages
        if let Some(bytes) = round.bcast_out() {
            broadcaster.send(Message::Bcast {
                from: round.index(),
                bytes: bytes.clone(),
            });
        }
        for (to, p2p) in round.p2ps_out().vec_ref().iter().enumerate() {
            if let Some(bytes) = p2p {
                broadcaster.send(Message::P2p {
                    from: round.index(),
                    to,
                    bytes: bytes.clone(),
                });
            }
        }
        // collect incoming messages
        while round.expecting_more_msgs_this_round() {
            match input.recv().expect("recv fail") {
                Message::Bcast { from, bytes } => round.bcast_in(from, &bytes),
                Message::P2p { from, to, bytes } => round.p2p_in(from, to, &bytes),
            }
        }

        party = round.execute_next_round();
    }
    match party {
        NotDone(_) => unreachable!(),
        Done(result) => result,
    }
}
