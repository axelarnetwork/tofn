use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::{DLogProof, ProveDLog},
        secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing},
        commitments::{
            hash_commitment::HashCommitment,
            traits::Commitment
        },
    },
    elliptic::curves::traits::{ECPoint},
};
use super::{R2State, R3Input, R3State, R3Bcast};

pub fn execute(state: R2State, msg: R3Input) -> (R3State, R3Bcast) {
    // assert!(!msg.other_r2_msgs.contains_key(&msg.my_uid));
    assert_eq!(
        msg.other_r2_msgs.keys().collect::<Vec<&String>>().sort_unstable(),
        state.others.keys().collect::<Vec<&String>>().sort_unstable()
    );

    // println!("party {}: p2p msgs I received: {:#?}", state.my_vss_index, msg.other_r2_msgs.iter().map(|(id,(_,p))| (id,p)).collect::<HashMap<&ID, &KeygenR2MsgOutP2p>>() );
    // println!("party {}: msgs I received: {:#?}", state.my_vss_index, msg.other_r2_msgs );

    let share_count = msg.other_r2_msgs.len() + 1;
    let mut public_key = state.y;
    let mut my_secret_key_share = state.my_share_of_u;

    for (id, (bcast, p2p)) in msg.other_r2_msgs {

        // let (other_r1_bcast, other_index) = state.others.get(&id).unwrap();
        let other_r1_bcast = state.others.get(&id).unwrap();
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &bcast.y.bytes_compressed_to_big_int(),
            &bcast.my_reveal,
        );
        assert!(other_r1_bcast.commit == com);

        let vss_scheme = VerifiableSS{ // cruft: needed for curv library
            parameters: ShamirSecretSharing{
                share_count,
                threshold: state.threshold,
            },
            commitments: bcast.my_vss_commitments,
        };
        // let vss_scheme = bcast.my_vss_scheme;
        // println!("validating share for party {:?}.  (share_count,threshold)=({},{})", id,vss_scheme.parameters.share_count,vss_scheme.parameters.threshold);
        assert!(vss_scheme.validate_share(&p2p.secret_share, state.my_vss_index).is_ok());
        assert!(vss_scheme.commitments[0].get_element() == bcast.y.get_element()); // TODO remove get_element()?

        public_key = public_key + bcast.y;
        my_secret_key_share = my_secret_key_share + p2p.secret_share;
    }

    let dlog_proof = DLogProof::prove(&my_secret_key_share);   
    (
        R3State {
            my_vss_index: state.my_vss_index,
            public_key,
            my_secret_key_share,
        },
        R3Bcast {
            dlog_proof,
        },
    )
}