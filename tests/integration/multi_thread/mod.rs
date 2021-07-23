use crate::common::keygen;
use broadcaster::Broadcaster;
use ecdsa::{elliptic_curve::sec1::FromEncodedPoint, hazmat::VerifyPrimitive};
use std::{convert::TryFrom, sync::mpsc, thread};
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::{
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sign::{new_sign, MessageDigest, SignParticipantIndex, SignParties},
    },
    sdk::api::PartyShareCounts,
};

#[cfg(feature = "malicious")]
use tofn::gg20::sign;

#[test]
fn basic_correctness() {
    set_up_logs();

    let party_share_counts = PartyShareCounts::from_vec(vec![1, 2, 3, 4]).unwrap(); // 10 total shares
    let threshold = 5;

    // keygen
    let keygen_shares = keygen::initialize_honest_parties(&party_share_counts, threshold);
    let (broadcaster, receivers) = Broadcaster::new(party_share_counts.total_share_count());
    let (result_sender, result_receiver) = mpsc::channel();
    for ((_, keygen_share), receiver) in keygen_shares.into_iter().zip(receivers.into_iter()) {
        let broadcaster = broadcaster.clone();
        let result_sender = result_sender.clone();
        thread::spawn(move || {
            result_sender.send(party::execute_protocol(keygen_share, receiver, broadcaster))
        });
    }
    drop(result_sender); // so that result_receiver can close

    // collect keygen output
    let mut secret_key_shares_unsorted: Vec<SecretKeyShare> = result_receiver
        .into_iter()
        .map(|output| {
            output
                .expect("internal tofn error")
                .expect("party finished in sad path")
        })
        .collect();
    secret_key_shares_unsorted.sort_by(|a, b| {
        a.share()
            .index()
            .as_usize()
            .cmp(&b.share().index().as_usize())
    });
    let secret_key_shares = VecMap::<KeygenPartyIndex, _>::from_vec(secret_key_shares_unsorted);

    // sign participants: 0,1,3 out of 0,1,2,3
    let sign_parties = {
        let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
        sign_parties.add(TypedUsize::from_usize(0)).unwrap();
        sign_parties.add(TypedUsize::from_usize(1)).unwrap();
        sign_parties.add(TypedUsize::from_usize(3)).unwrap();
        sign_parties
    };
    let keygen_share_ids = VecMap::<SignParticipantIndex, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );
    let sign_share_count = party_share_counts
        .subset(&sign_parties)
        .unwrap()
        .into_iter()
        .sum();

    // sign
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();
    let sign_shares = keygen_share_ids.map(|keygen_share_id| {
        let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
        new_sign(
            secret_key_share.group(),
            secret_key_share.share(),
            &sign_parties,
            &msg_to_sign,
            #[cfg(feature = "malicious")]
            sign::malicious::Behaviour::Honest,
        )
        .unwrap()
    });
    let (broadcaster, receivers) = Broadcaster::new(sign_share_count);
    let (result_sender, result_receiver) = mpsc::channel();
    for ((_, sign_share), receiver) in sign_shares.into_iter().zip(receivers.into_iter()) {
        let broadcaster = broadcaster.clone();
        let result_sender = result_sender.clone();
        thread::spawn(move || {
            result_sender.send(party::execute_protocol(sign_share, receiver, broadcaster))
        });
    }
    drop(result_sender); // so that result_receiver can close

    // collect sign output
    let signatures: VecMap<SignParticipantIndex, _> = result_receiver
        .into_iter()
        .map(|output| {
            output
                .expect("internal tofn error")
                .expect("party finished in sad path")
        })
        .collect();

    // grab pubkey bytes from one of the shares
    let pubkey_bytes = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .pubkey_bytes();

    // verify a signature
    let pubkey = k256::AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap(),
    )
    .unwrap();
    let sig = k256::ecdsa::Signature::from_der(signatures.get(TypedUsize::from_usize(0)).unwrap())
        .unwrap();
    assert!(pubkey
        .verify_prehashed(&k256::Scalar::from(&msg_to_sign), &sig)
        .is_ok());
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
        pub fn new(share_count: usize) -> (Self, Vec<Receiver<T>>) {
            // can't build two vecs from one iterator
            // so we need to do it the old-fashioned way
            let mut senders = Vec::with_capacity(share_count);
            let mut receivers = Vec::with_capacity(share_count);
            for _ in 0..share_count {
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

fn set_up_logs() {
    // set up environment variable for log level
    // set up an event subscriber for logs
    let _ = tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(tracing::Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .try_init();
}
