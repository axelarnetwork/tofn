use crate::{
    hash,
    k256_serde::to_bytes,
    paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        collections::{HoleVecMap, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        protocol::{
            api::{BytesVec, TofnResult},
            implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
            no_messages,
        },
    },
};
use ecdsa::elliptic_curve::Field;
use serde::{Deserialize, Serialize};

use super::{r2, Peers, SignParticipantIndex, SignProtocolBuilder};

#[allow(non_snake_case)]
pub struct R1 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: k256::Scalar,
    pub peers: Peers,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i_commit: hash::Output,
    pub k_i_ciphertext: paillier_k256::Ciphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof: paillier_k256::zk::range::Proof,
}

impl no_messages::Executer for R1 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        _participants_count: usize,
        sign_id: TypedUsize<Self::Index>,
    ) -> TofnResult<SignProtocolBuilder> {
        let w_i = self.secret_key_share.share.x_i.unwrap()
            * &vss_k256::lagrange_coefficient(
                sign_id.as_usize(),
                &self
                    .peers
                    .iter()
                    .map(|(_, k)| k.as_usize())
                    .collect::<Vec<_>>(),
            );

        let k_i = k256::Scalar::random(rand::thread_rng());
        let gamma_i = k256::Scalar::random(rand::thread_rng());
        let Gamma_i = k256::ProjectivePoint::generator() * gamma_i;
        let (Gamma_i_commit, Gamma_i_reveal) = hash::commit(to_bytes(&Gamma_i));

        // initiate MtA protocols for
        // 1. k_i (me) * gamma_j (other)
        // 2. k_i (me) * w_j (other)
        // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
        // range proof must be custom for each other party
        // but k_i_ciphertext can be broadcast to all parties

        let ek = &self
            .secret_key_share
            .group
            .all_shares
            .get(self.keygen_id)?
            .ek;
        let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

        let mut p2ps_out = Vec::with_capacity(self.peers.len());

        for (_, &keygen_peer_id) in &self.peers {
            let peer_zkp = &self
                .secret_key_share
                .group
                .all_shares
                .get(keygen_peer_id)?
                .zkp;
            let range_proof = peer_zkp.range_proof(
                &paillier_k256::zk::range::Statement {
                    ciphertext: &k_i_ciphertext,
                    ek,
                },
                &paillier_k256::zk::range::Witness {
                    msg: &k_i,
                    randomness: &k_i_randomness,
                },
            );

            let p2p_out = serialize(&P2p { range_proof })?;

            p2ps_out.push(p2p_out);
        }

        let p2ps_out = HoleVecMap::from_vecmap(VecMap::from_vec(p2ps_out), sign_id)?;

        // Alternative approach
        // let p2ps_out = self.other_participants.map_ref(|(_, keygen_peer_id)| {
        //     let peer_zkp = &self.secret_key_share.group.all_shares.get(keygen_peer_id)?.zkp;
        //     let range_proof = peer_zkp.range_proof(
        //         &paillier_k256::zk::range::Statement {
        //             ciphertext: &k_i_ciphertext,
        //             ek: ek,
        //         },
        //         &paillier_k256::zk::range::Witness {
        //             msg: &k_i,
        //             randomness: &k_i_randomness,
        //         },
        //     );

        //     serialize(&P2p {
        //         range_proof,
        //     })
        // })?;

        let bcast_out = serialize(&Bcast {
            Gamma_i_commit,
            k_i_ciphertext,
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r2::R2 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                other_participants: self.peers,
                keygen_id: self.keygen_id,
                gamma_i,
                Gamma_i_reveal,
                w_i,
            }),
            bcast_out,
            p2ps_out,
        }))
    }
}
