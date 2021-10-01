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
    round_num: usize,
    bytes: BytesVec,
}

pub fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    mut party: Protocol<F, K, P, MAX_MSG_IN_LEN>,
    input: Receiver<Message<P>>,
    broadcaster: Broadcaster<Message<P>>,
) -> TofnResult<ProtocolOutput<F, P>>
where
    P: Clone,
{
    // We keep track of future messages from the next round due to
    // concurrency issues mentioned in https://github.com/axelarnetwork/tofn/issues/102
    // NOTE: This is only a workaround for tests where ordering is not guaranteed
    // unlike when using a blockchain.
    // collect incoming messages
    let mut round_num = 0;
    let mut future_messages: Vec<Message<P>> = Vec::new();

    while let Protocol::NotDone(mut round) = party {
        let party_id = round.info().party_id();

        // send outgoing messages
        if let Some(bytes) = round.bcast_out() {
            broadcaster.send(Message {
                from: party_id,
                round_num,
                bytes: bytes.clone(),
            });
        }

        if let Some(p2ps_out) = round.p2ps_out() {
            for (_, bytes) in p2ps_out.iter() {
                broadcaster.send(Message {
                    from: party_id,
                    round_num,
                    bytes: bytes.clone(),
                });
            }
        }

        // Replay future messages
        for msg in future_messages.into_iter() {
            round.msg_in(msg.from, &msg.bytes)?;
        }

        future_messages = Vec::new();

        while round.expecting_more_msgs_this_round() {
            let msg = input.recv().expect("recv fail");

            if msg.round_num == round_num + 1 {
                future_messages.push(msg);
            } else if msg.round_num == round_num {
                round.msg_in(msg.from, &msg.bytes)?;
            } else {
                error!(
                    "Party {} received a message from an unsupported round {}",
                    party_id, msg.round_num
                );
                return Err(TofnFatal);
            }
        }

        party = round.execute_next_round()?;

        round_num += 1;
    }

    match party {
        Protocol::NotDone(_) => unreachable!(),
        Protocol::Done(result) => Ok(result),
    }
}
