use crate::zkp::range;
use serde::{Deserialize, Serialize};

use crate::{fillvec::FillVec, protocol::gg20::vss};
use curv::{
    // arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
    FE,
    GE,
};
use multi_party_ecdsa::utilities::mta;
// use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

use super::{Sign, Status};

// round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub commit: BigInt,
    pub encrypted_ecdsa_nonce_summand: mta::MessageA,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof: range::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_secret_key_summand: FE,
    pub(super) my_secret_blind_summand: FE,
    pub(super) my_public_blind_summand: GE,
    pub(super) my_reveal: BigInt,
    pub(super) my_ecdsa_nonce_summand: FE,
    // TODO pair these next two fields in a range::Witness
    // problem: range::Witness has a lifetime parameter---eliminate it
    pub(super) my_encrypted_ecdsa_nonce_summand: BigInt,
    pub(super) my_encrypted_ecdsa_nonce_summand_randomness: BigInt,
}

impl Sign {
    // immutable &self: do not modify existing self state, only add more
    pub(super) fn r1(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::New));
        let my_secret_key_summand // w_i
            = self.my_secret_key_share.my_ecdsa_secret_key_share
            * vss::lagrangian_coefficient( // l_i
                self.my_secret_key_share.share_count,
                self.my_secret_key_share.my_index,
                &self.participant_indices,
            );
        let my_secret_blind_summand = FE::new_random(); // gamma_i
        let my_public_blind_summand = GE::generator() * my_secret_blind_summand; // g_gamma_i
        let my_ecdsa_nonce_summand = FE::new_random(); // k_i
        let (commit, my_reveal) = HashCommitment::create_commitment(
            &my_public_blind_summand.bytes_compressed_to_big_int(),
        );

        // initiate MtA protocols for
        // 1. my_ecdsa_nonce_summand (me) * my_secret_blind_summand (other)
        // 2. my_ecdsa_nonce_summand (me) * my_secret_key_summand (other)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both
        // re-use encrypted_ecdsa_nonce_summand for all other parties
        let my_ek = &self.my_secret_key_share.my_ek;
        let (encrypted_ecdsa_nonce_summand, my_encrypted_ecdsa_nonce_summand_randomness) =
            mta::MessageA::a(&my_ecdsa_nonce_summand, my_ek);
        let my_encrypted_ecdsa_nonce_summand = encrypted_ecdsa_nonce_summand.c.clone();

        // TODO these variable names are getting ridiculous
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let range_proof = other_zkp.range_proof(
                &range::Statement {
                    ciphertext: &my_encrypted_ecdsa_nonce_summand,
                    ek: my_ek,
                },
                &range::Witness {
                    msg: &my_ecdsa_nonce_summand,
                    randomness: &my_encrypted_ecdsa_nonce_summand_randomness,
                },
            );
            out_p2ps.insert(i, P2p { range_proof }).unwrap();
        }

        (
            State {
                my_secret_key_summand,
                my_secret_blind_summand,
                my_public_blind_summand,
                my_reveal,
                my_ecdsa_nonce_summand,
                my_encrypted_ecdsa_nonce_summand,
                my_encrypted_ecdsa_nonce_summand_randomness,
            },
            Bcast {
                commit,
                encrypted_ecdsa_nonce_summand,
                // TODO broadcast GE::generator() * self.my_secret_key_share.my_ecdsa_secret_key_share ? https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_sign_client.rs#L138
            },
            out_p2ps,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{
        protocol::{
            gg20::keygen::{tests::execute_keygen, SecretKeyShare},
            gg20::tests::sign::{MSG_TO_SIGN, TEST_CASES},
            tests::execute_protocol_vec,
            Protocol,
        },
        zkp::range::tests::corrupt_proof,
    };

    #[test]
    fn one_bad_proof() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if participant_indices.len() < 2 {
                continue; // need at least 2 participants for this test
            }
            let key_shares = execute_keygen(*share_count, *threshold);
            one_bad_proof_inner(&key_shares, participant_indices, &MSG_TO_SIGN);
        }
    }

    fn one_bad_proof_inner(
        key_shares: &[SecretKeyShare],
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) {
        assert!(participant_indices.len() > 1);
        let (criminal, victim) = (1, 0);

        let mut participants: Vec<Sign> = participant_indices
            .iter()
            .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
            .collect();

        // execute round 1 all participants and store their outputs
        let mut all_r1_bcasts = FillVec::with_len(participants.len());
        let mut all_r1_p2ps = Vec::with_capacity(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            let (state, bcast, p2ps) = participant.r1();
            participant.r1state = Some(state);
            participant.status = Status::R1;
            all_r1_bcasts.insert(i, bcast).unwrap();
            all_r1_p2ps.push(p2ps);
        }

        // corrupt the proof from party `criminal` to party `victim`
        let proof = &mut all_r1_p2ps[criminal].vec_ref_mut()[victim]
            .as_mut()
            .unwrap()
            .range_proof;
        *proof = corrupt_proof(proof);

        // deliver round 1 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r1p2ps = all_r1_p2ps.clone();
            participant.in_r1bcasts = all_r1_bcasts.clone();
        }

        // execute round 2 all participants and store their outputs
        let mut all_r2_p2ps = Vec::with_capacity(participants.len());
        let mut all_r2_bcasts_fail = FillVec::with_len(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            match participant.r2() {
                r2::Output::Success { state, out_p2ps } => {
                    if i == victim {
                        panic!(
                            "r2 party {} expect failure but found success",
                            participant.my_secret_key_share.my_index
                        );
                    }
                    participant.r2state = Some(state);
                    all_r2_p2ps.push(out_p2ps);
                }
                r2::Output::Fail { out_bcast } => {
                    if i != victim {
                        panic!(
                            "r2 party {} expect success but found failure with culprits {:?}",
                            participant.my_secret_key_share.my_index, out_bcast.culprits
                        );
                    }
                    all_r2_bcasts_fail.insert(i, out_bcast).unwrap();
                    all_r2_p2ps.push(FillVec::with_len(0)); // dummy TODO use FillVec instead of Vec?
                }
            }
        }

        // deliver round 2 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r2p2ps = all_r2_p2ps.clone();
            participant.in_r2bcasts_fail = all_r2_bcasts_fail.clone();

            // all participants transition to R2Fail because they all received at least one r2::FailBcast
            participant.status = Status::R2Fail;
        }

        // execute round 2 sad path all participants and store their outputs
        let mut all_culprit_lists = Vec::with_capacity(participants.len());
        for participant in participants.iter_mut() {
            let culprits = participant.r3fail();
            participant.status = Status::Fail;
            all_culprit_lists.push(culprits);
        }

        // TEST: everyone correctly computed the culprit list
        let actual_culprits: Vec<usize> = vec![criminal];
        for culprit_list in all_culprit_lists {
            assert_eq!(culprit_list, actual_culprits);
        }
    }

    struct BadProof {
        s: Sign,
        victim: usize,
    }

    impl BadProof {
        pub fn new(
            my_secret_key_share: &SecretKeyShare,
            participant_indices: &[usize],
            msg_to_sign: &[u8],
            victim: usize,
        ) -> Result<Self, ParamsError> {
            Ok(Self {
                s: Sign::new(my_secret_key_share, participant_indices, msg_to_sign)?,
                victim,
            })
        }
        pub fn get_result(&self) -> Option<Result<&Asn1Signature, &Vec<usize>>> {
            self.s.get_result()
        }
    }

    // I sure do wish Rust would support easy delegation https://github.com/rust-lang/rfcs/pull/2393
    impl Protocol for BadProof {
        fn next_round(&mut self) -> crate::protocol::ProtocolResult {
            // TODO fix bad design - code copied from impl Protocol
            // this test could be broken by changes to protocol.rs
            match &self.s.status {
                Status::New => {
                    if self.expecting_more_msgs_this_round() {
                        return Err(From::from("can't proceed yet"));
                    }
                    let (state, bcast, mut p2ps) = self.s.r1();

                    // corrupt the proof to self.victim
                    let proof = &mut p2ps.vec_ref_mut()[self.victim]
                        .as_mut()
                        .unwrap()
                        .range_proof;
                    *proof = corrupt_proof(proof);

                    self.s.update_state_r1(state, bcast, p2ps)
                }
                _ => self.s.next_round(),
            }
        }

        fn set_msg_in(&mut self, msg: &[u8]) -> crate::protocol::ProtocolResult {
            self.s.set_msg_in(msg)
        }

        fn get_bcast_out(&self) -> &Option<MsgBytes> {
            self.s.get_bcast_out()
        }

        fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
            self.s.get_p2p_out()
        }

        fn expecting_more_msgs_this_round(&self) -> bool {
            self.s.expecting_more_msgs_this_round()
        }

        fn done(&self) -> bool {
            self.s.done()
        }
    }

    #[test]
    fn one_bad_proof_protocol() {
        one_bad_proof_protocol_inner(false)
    }

    #[test]
    fn one_bad_proof_protocol_with_self_delivery() {
        one_bad_proof_protocol_inner(true)
    }

    fn one_bad_proof_protocol_inner(allow_self_delivery: bool) {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if participant_indices.len() < 2 {
                continue; // need at least 2 participants for this test
            }
            let key_shares = execute_keygen(*share_count, *threshold);

            let mut bad_guy = BadProof::new(
                &key_shares[participant_indices[0]],
                &participant_indices,
                &MSG_TO_SIGN,
                1,
            )
            .unwrap();
            let mut good_guys: Vec<Sign> = participant_indices
                .iter()
                .skip(1)
                .map(|i| Sign::new(&key_shares[*i], &participant_indices, &MSG_TO_SIGN).unwrap())
                .collect();

            let mut protocols: Vec<&mut dyn Protocol> = vec![&mut bad_guy as &mut dyn Protocol];
            protocols.append(
                &mut good_guys
                    .iter_mut()
                    .map(|p| p as &mut dyn Protocol)
                    .collect(),
            );

            execute_protocol_vec(&mut protocols, allow_self_delivery);

            // TEST: everyone correctly computed the culprit list
            let actual_culprits: Vec<usize> = vec![0];
            assert_eq!(bad_guy.get_result().unwrap().unwrap_err(), &actual_culprits);
            for good_guy in good_guys {
                assert_eq!(
                    good_guy.get_result().unwrap().unwrap_err(),
                    &actual_culprits
                );
            }
        }
    }
}
