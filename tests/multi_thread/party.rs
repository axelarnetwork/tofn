use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    refactor::{protocol::Protocol, BytesVec},
    vecmap::Index,
};

// #[derive(Clone)]
pub enum Message<K> {
    Bcast {
        from: Index<K>,
        bytes: BytesVec,
    },
    P2p {
        from: usize,
        to: usize,
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
        if let Some(bytes) = round.bcast_out() {
            broadcaster.send(Message::Bcast {
                from: Index::from_usize(round.index()),
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
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => result,
    }
}
