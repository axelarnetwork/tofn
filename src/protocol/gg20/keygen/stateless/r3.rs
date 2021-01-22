use super::{super::super::vss, R2Bcast, R2P2p, R2State, R3Bcast, R3State};
use curv::{
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::{DLogProof, ProveDLog},
    },
    elliptic::curves::traits::ECPoint,
};

pub fn execute(
    state: R2State,
    in_bcasts: &[Option<R2Bcast>],
    in_p2ps: &[Option<R2P2p>],
) -> (R3State, R3Bcast) {
    assert_eq!(in_bcasts.len(), state.share_count);
    assert_eq!(in_p2ps.len(), state.share_count);

    let mut public_key = state.my_ecdsa_public_summand;
    let mut my_secret_key_share = state.my_share_of_my_ecdsa_secret_summand;

    for i in 0..state.share_count {
        if i == state.my_index {
            continue;
        }
        let bcast = in_bcasts[i].clone().expect(&format!(
            "party {} says: missing bcast input for party {}",
            state.my_index, i
        ));
        let p2p = in_p2ps[i].clone().expect(&format!(
            "party {} says: missing p2p input for party {}",
            state.my_index, i
        ));
        let ecdsa_public_summand = &bcast.secret_share_commitments[0];
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &ecdsa_public_summand.bytes_compressed_to_big_int(),
            &bcast.reveal,
        );
        assert!(state.all_commits[i] == com);
        assert!(vss::validate_share(
            &bcast.secret_share_commitments,
            &p2p.ecdsa_secret_summand_share,
            state.my_share_index
        )
        .is_ok());

        public_key = public_key + ecdsa_public_summand;
        my_secret_key_share = my_secret_key_share + p2p.ecdsa_secret_summand_share;
    }

    let my_bcast = R3Bcast {
        dlog_proof: DLogProof::prove(&my_secret_key_share),
    };
    (
        R3State {
            share_count: state.share_count,
            my_index: state.my_index,
            my_share_index: state.my_share_index,
            ecdsa_public_key: public_key,
            my_ecdsa_secret_key_share: my_secret_key_share,
            // my_r2_state: state,
            // in_bcasts,
            // my_output: my_bcast.clone(),
        },
        my_bcast,
    )
}
