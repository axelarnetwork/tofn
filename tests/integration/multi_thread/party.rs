use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    collections::TypedUsize,
    sdk::api::{BytesVec, Protocol, ProtocolOutput, TofnResult},
};
use tracing::info;

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
    let mut r = 0;

    while let Protocol::NotDone(mut round) = party {
        let id = round.info().share_info().share_id();

        info!("Peer {}, Round {}: sending out messages", id, r);
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

        info!("Peer {}, Round {}: Receiving messages at the end of round", id, r);

        // collect incoming messages
        while round.expecting_more_msgs_this_round() {
            let msg = input.recv().expect("recv fail");
            info!("Peer {}, Round {}: received message from {}", id, r, msg.from);
            round.msg_in(msg.from, &msg.bytes)?;
        }

        r += 1;
        info!("Peer {}, Round {}: starting", id, r);

        party = round.execute_next_round()?;
    }
    match party {
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => Ok(result),
    }
}
