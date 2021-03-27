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
            gg20::sign::{
                protocol::{MsgMeta, MsgType},
                tests::{MSG_TO_SIGN, TEST_CASES},
            },
            tests::execute_protocol_vec,
            Protocol,
        },
        zkp::range::tests::corrupt_proof,
    };

    struct BadProof(Sign); // newtype pattern + delegation to emulate struct embedding

    impl BadProof {
        pub fn new(
            my_secret_key_share: &SecretKeyShare,
            participant_indices: &[usize],
            msg_to_sign: &[u8],
        ) -> Result<Self, ParamsError> {
            Ok(Self(Sign::new(
                my_secret_key_share,
                participant_indices,
                msg_to_sign,
            )?))
        }
    }

    // I sure do wish Rust would support easy delegation https://github.com/rust-lang/rfcs/pull/2393
    impl Protocol for BadProof {
        fn next_round(&mut self) -> crate::protocol::ProtocolResult {
            match &self.0.status {
                Status::New => {
                    if self.expecting_more_msgs_this_round() {
                        return Err(From::from("can't prceed yet"));
                    }
                    let (state, bcast, p2ps) = self.0.r1();
                    self.0.out_r1bcast = Some(bincode::serialize(&MsgMeta {
                        msg_type: MsgType::R1Bcast,
                        from: self.0.my_participant_index,
                        payload: bincode::serialize(&bcast)?,
                    })?);
                    let mut out_r1p2ps = Vec::with_capacity(self.0.participant_indices.len());
                    for (to, opt) in p2ps.into_vec().into_iter().enumerate() {
                        if let Some(p2p) = opt {
                            out_r1p2ps.push(Some(bincode::serialize(&MsgMeta {
                                msg_type: MsgType::R1P2p { to },
                                from: self.0.my_participant_index,
                                payload: bincode::serialize(&p2p)?,
                            })?));
                        } else {
                            out_r1p2ps.push(None);
                        }
                    }
                    self.0.out_r1p2ps = Some(out_r1p2ps);
                    self.0.r1state = Some(state);
                    self.0.status = Status::R1;
                    Ok(())
                }
                _ => self.0.next_round(),
            }
        }

        fn set_msg_in(&mut self, msg: &[u8]) -> crate::protocol::ProtocolResult {
            self.0.set_msg_in(msg)
        }

        fn get_bcast_out(&self) -> &Option<MsgBytes> {
            self.0.get_bcast_out()
        }

        fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
            self.0.get_p2p_out()
        }

        fn expecting_more_msgs_this_round(&self) -> bool {
            self.0.expecting_more_msgs_this_round()
        }

        fn done(&self) -> bool {
            self.0.done()
        }
    }

    #[test]
    fn one_bad_proof_protocol() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if participant_indices.len() < 2 {
                continue; // need at least 2 participants for this test
            }
            let key_shares = execute_keygen(*share_count, *threshold);

            let mut bad_guy = BadProof::new(
                &key_shares[participant_indices[0]],
                &participant_indices,
                &MSG_TO_SIGN,
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

            execute_protocol_vec(&mut protocols);
        }
    }
}
