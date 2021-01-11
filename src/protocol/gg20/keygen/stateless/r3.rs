use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::{DLogProof, ProveDLog},
        commitments::{
            hash_commitment::HashCommitment,
            traits::Commitment
        },
    },
    elliptic::curves::traits::{ECPoint},
};
use super::{R2State, R3Input, R3State, R3Bcast, super::super::vss};

pub fn execute(state: R2State, input: R3Input) -> (R3State, R3Bcast) {
    // assert!(!msg.other_r2_msgs.contains_key(&msg.my_uid));
    
    assert!( eq_lists(
        &input.other_r2_msgs.keys().collect::<Vec<&String>>(),
        &state.input.other_r1_bcasts.keys().collect::<Vec<&String>>()
        )
    );

    let mut public_key = state.get_ecdsa_public_summand();
    let mut my_secret_key_share = state.my_share_of_my_ecdsa_secret_summand;

    for (id, (bcast, p2p)) in &input.other_r2_msgs {
        let other_r1_bcast = state.input.other_r1_bcasts.get(id).unwrap();
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &bcast.get_ecdsa_public_summand().bytes_compressed_to_big_int(),
            &bcast.reveal,
        );
        assert!(other_r1_bcast.commit == com);
        assert!(
            vss::validate_share(
                &bcast.secret_share_commitments,
                &p2p.ecdsa_secret_summand_share,
                state.my_share_index
            ).is_ok()
        );

        public_key = public_key + bcast.get_ecdsa_public_summand();
        my_secret_key_share = my_secret_key_share + p2p.ecdsa_secret_summand_share;
    }

    let my_bcast = R3Bcast {
        dlog_proof: DLogProof::prove(&my_secret_key_share)
    };
    (
        R3State {
            // my_vss_index: state.my_share_index,
            ecdsa_public_key: public_key,
            my_ecdsa_secret_key_share: my_secret_key_share,
            my_r2_state: state,
            input,
            my_output: my_bcast.clone(),
        },
        my_bcast,
    )
}

// TODO generic helper---where to put it?
fn eq_lists<T>(a: &[T], b: &[T]) -> bool
    where T: PartialEq + Ord,
{
    let mut a: Vec<_> = a.iter().collect();
    let mut b: Vec<_> = b.iter().collect();
    a.sort();
    b.sort();

    a == b
}