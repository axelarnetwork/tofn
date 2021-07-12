use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    refactor::api::{BytesVec, Protocol, ProtocolOutput},
    vecmap::{Behave, TypedUsize},
};

#[derive(Clone)]
pub enum Message<K>
where
    K: Behave,
{
    Bcast {
        from: TypedUsize<K>,
        bytes: BytesVec,
    },
    P2p {
        from: TypedUsize<K>,
        to: TypedUsize<K>,
        bytes: BytesVec,
    },
}

// /// Manually impl `Clone` because https://stackoverflow.com/a/31371094
// impl<K> Clone for Message<K> {
//     fn clone(&self) -> Self {
//         use Message::*;
//         match self {
//             Bcast { from, bytes } => Bcast {
//                 from: from.clone(),
//                 bytes: bytes.clone(),
//             },
//             P2p { from, to, bytes } => P2p {
//                 from: *from,
//                 to: *to,
//                 bytes: bytes.clone(),
//             },
//         }
//     }
// }

pub fn execute_protocol<F, K>(
    mut party: Protocol<F, K>,
    input: Receiver<Message<K>>,
    broadcaster: Broadcaster<Message<K>>,
) -> ProtocolOutput<F, K>
where
    K: Behave,
{
    while let Protocol::NotDone(mut round) = party {
        // send outgoing messages
        if let Some(bytes) = round.bcast_out() {
            broadcaster.send(Message::Bcast {
                from: round.index(),
                bytes: bytes.clone(),
            });
        }
        if let Some(p2ps_out) = round.p2ps_out() {
            for (to, bytes) in p2ps_out.iter() {
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
