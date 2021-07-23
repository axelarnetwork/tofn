use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    collections::TypedUsize,
    sdk::api::{BytesVec, Protocol, ProtocolOutput, TofnResult},
};

#[derive(Clone)]
pub struct Message<P> {
    from: TypedUsize<P>,
    bytes: BytesVec,
}

pub fn execute_protocol<F, K, P>(
    mut party: Protocol<F, K, P>,
    input: Receiver<Message<P>>,
    broadcaster: Broadcaster<Message<P>>,
) -> TofnResult<ProtocolOutput<F, P>>
where
    P: Clone,
{
    while let Protocol::NotDone(mut round) = party {
        // send outgoing messages
        if let Some(bytes) = round.bcast_out() {
            broadcaster.send(Message {
                from: round.info().party_id(),
                bytes: bytes.clone(),
            });
        }
        if let Some(p2ps_out) = round.p2ps_out() {
            for (_, bytes) in p2ps_out.iter() {
                broadcaster.send(Message {
                    from: round.info().party_id(),
                    bytes: bytes.clone(),
                });
            }
        }
        // collect incoming messages
        while round.expecting_more_msgs_this_round() {
            let msg = input.recv().expect("recv fail");
            round.msg_in(msg.from, &msg.bytes)?;
        }

        party = round.execute_next_round()?;
    }
    match party {
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => Ok(result),
    }
}
