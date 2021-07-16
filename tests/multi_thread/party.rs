use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    refactor::collections::TypedUsize,
    refactor::protocol::api::{BytesVec, Protocol, ProtocolOutput, TofnResult},
};

#[derive(Clone)]
pub enum Message<K> {
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

pub fn execute_protocol<F, K, P>(
    mut party: Protocol<F, K, P>,
    input: Receiver<Message<K>>,
    broadcaster: Broadcaster<Message<K>>,
) -> TofnResult<ProtocolOutput<F, K>>
where
    K: Clone,
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
                Message::Bcast { from, bytes } => round.bcast_in(from, &bytes)?,
                Message::P2p { from, to, bytes } => round.p2p_in(from, to, &bytes)?,
            }
        }

        party = round.execute_next_round()?;
    }
    match party {
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => Ok(result),
    }
}
