use super::Broadcaster;
use std::sync::mpsc::Receiver;

// can't use `Protocol::*` because Rust does not support
// `use` statements for type aliased enums :(
// https://github.com/rust-lang/rust/issues/83248
use tofn::{
    collections::TypedUsize,
    sdk::api::{BytesVec, Protocol, ProtocolOutput, TofnFatal, TofnResult},
};
use tracing::error;

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

        // We keep track of when all parties are done receiving protocol messages
        // This way all parties move into the next round together to avoid
        // concurrency issues mentioned in https://github.com/axelarnetwork/tofn/issues/102
        // NOTE: This is only a workaround for tests where ordering is not guaranteed
        // unlike when using a blockchain.
        let mut done_parties: usize = 0;

        // collect incoming messages
        while round.expecting_more_msgs_this_round() {
            let msg = input.recv().expect("recv fail");

            if msg.bytes.is_empty() {
                done_parties += 1;
            } else {
                round.msg_in(msg.from, &msg.bytes)?;
            }
        }

        // Send a signal to all parties that we've received all messages
        broadcaster.send(Message {
            from: round.info().party_id(),
            bytes: Vec::new(),
        });

        while done_parties < round.info().party_share_counts().total_share_count() {
            let msg = input.recv().expect("recv fail");

            if msg.bytes.is_empty() {
                done_parties += 1;
            } else {
                error!(
                    "Party {} received unexpected message from party {}",
                    round.info().party_id(),
                    msg.from
                );
                return Err(TofnFatal);
            }
        }

        party = round.execute_next_round()?;
    }

    match party {
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => Ok(result),
    }
}
