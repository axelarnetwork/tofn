use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    refactor::{protocol::Protocol, BytesVec},
    vecmap::Index,
};
use tracing::error;

// #[derive(Clone)]
pub enum Message<K> {
    Bcast {
        from: Index<K>,
        bytes: BytesVec,
    },
    P2p {
        from: Index<K>,
        to: Index<K>,
        bytes: BytesVec,
    },
}

/// Manually impl `Clone` because https://stackoverflow.com/a/31371094
impl<K> Clone for Message<K> {
    fn clone(&self) -> Self {
        use Message::*;
        match self {
            Bcast { from, bytes } => Bcast {
                from: from.clone(),
                bytes: bytes.clone(),
            },
            P2p { from, to, bytes } => P2p {
                from: *from,
                to: *to,
                bytes: bytes.clone(),
            },
        }
    }
}

pub fn execute_protocol<F, I>(
    mut party: Protocol<F, I>,
    input: Receiver<Message<I>>,
    broadcaster: Broadcaster<Message<I>>,
) -> F {
    while let Protocol::NotDone(mut round) = party {
        // send outgoing messages
        if let Some(bcast_out) = round.bcast_out() {
            if let Ok(bytes) = bcast_out {
                broadcaster.send(Message::Bcast {
                    from: Index::from_usize(round.index()),
                    bytes: bytes.clone(),
                });
            } else {
                error!("missing bcast from party {}", round.index());
            }
        }
        if let Some(p2ps_out) = round.p2ps_out() {
            if let Ok(p2ps_out) = p2ps_out {
                for (to, bytes) in p2ps_out.iter() {
                    broadcaster.send(Message::P2p {
                        from: Index::from_usize(round.index()),
                        to: to,
                        bytes: bytes.clone(),
                    });
                }
            } else {
                error!("missing all p2ps from party {}", round.index());
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
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => result,
    }
}
