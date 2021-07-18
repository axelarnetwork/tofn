use broadcaster::Broadcaster;
use rand::RngCore;
use std::{sync::mpsc, thread};
use tofn::{
    refactor::collections::TypedUsize,
    refactor::{
        collections::VecMap,
        keygen::{new_keygen, KeygenProtocol, RealKeygenPartyIndex, SecretKeyShare},
    },
};

#[cfg(feature = "malicious")]
use tofn::refactor::keygen::malicious::Behaviour::Honest;

// TODO generic over final output F

#[test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    // TODO TEMPORARY one share per party
    let party_share_counts: VecMap<RealKeygenPartyIndex, usize> =
        (0..share_count).map(|_| 1).collect();

    let parties: Vec<KeygenProtocol> = (0..share_count)
        .map(|index| {
            let mut secret_recovery_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut secret_recovery_key);
            new_keygen(
                party_share_counts.clone(),
                threshold,
                TypedUsize::from_usize(index),
                &secret_recovery_key,
                session_nonce,
                #[cfg(feature = "malicious")]
                Honest,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    let (broadcaster, receivers) = Broadcaster::new(share_count);
    let (result_sender, result_receiver) = mpsc::channel();

    for (party, receiver) in parties.into_iter().zip(receivers.into_iter()) {
        let broadcaster = broadcaster.clone();
        let result_sender = result_sender.clone();
        thread::spawn(move || {
            result_sender.send(party::execute_protocol(party, receiver, broadcaster))
        });
    }

    drop(result_sender); // so that result_receiver can close

    let results: Vec<SecretKeyShare> = result_receiver
        .into_iter()
        .map(|res| {
            res.expect("internal tofn error")
                .expect("party finished in sad path")
        })
        .collect();

    println!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        println!("party {} secret info: {:?}", i, result.share);
    }
}

mod broadcaster {
    use std::sync::mpsc::{self, Receiver, Sender};

    #[derive(Clone)]
    pub struct Broadcaster<T> {
        senders: Vec<Sender<T>>,
    }

    impl<T> Broadcaster<T>
    where
        T: Clone,
    {
        pub fn new(party_count: usize) -> (Self, Vec<Receiver<T>>) {
            // can't build two vecs from one iterator
            // so we need to do it the old-fashioned way
            let mut senders = Vec::with_capacity(party_count);
            let mut receivers = Vec::with_capacity(party_count);
            for _ in 0..party_count {
                let (sender, receiver) = mpsc::channel();
                senders.push(sender);
                receivers.push(receiver);
            }
            (Self { senders }, receivers)
        }
        pub fn send(&self, msg: T) {
            for sender in self.senders.iter() {
                sender.send(msg.clone()).expect("broadcast fail");
            }
        }
    }
}
mod party;
