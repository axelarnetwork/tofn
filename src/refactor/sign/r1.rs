use crate::{
    corrupt,
    crypto_tools::vss,
    hash,
    k256_serde::to_bytes,
    paillier_k256,
    refactor::{
        collections::TypedUsize,
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, TofnResult},
            implementer_api::{
                no_messages, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder,
            },
        },
    },
};
use ecdsa::elliptic_curve::Field;
use k256::Scalar;
use serde::{Deserialize, Serialize};

use super::{r2, Participants, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R1 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
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
        info: &ProtocolInfo<Self::Index>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();

        let lambda_i_S = &vss::lagrange_coefficient(
            sign_id.as_usize(),
            &self
                .participants
                .iter()
                .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
                .collect::<Vec<_>>(),
        );

        let w_i = self.secret_key_share.share().x_i().unwrap() * lambda_i_S;

        let k_i = k256::Scalar::random(rand::thread_rng());
        let gamma_i = k256::Scalar::random(rand::thread_rng());
        let Gamma_i = k256::ProjectivePoint::generator() * gamma_i;
        let (Gamma_i_commit, Gamma_i_reveal) = hash::commit(to_bytes(&Gamma_i));

        corrupt!(gamma_i, self.corrupt_gamma_i(info.share_id(), gamma_i));

        // initiate MtA protocols for
        // 1. k_i (me) * gamma_j (other)
        // 2. k_i (me) * w_j (other)
        // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
        // range proof must be custom for each other party
        // but k_i_ciphertext can be broadcast to all parties

        let ek = &self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.keygen_id)?
            .ek();
        let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

        let p2ps_out = self.peers.map_ref(|(_peer_id, &keygen_peer_id)| {
            let peer_zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .zkp();

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

            corrupt!(
                range_proof,
                self.corrupt_range_proof(info.share_id(), _peer_id, range_proof)
            );

            serialize(&P2p { range_proof })
        })?;

        let bcast_out = serialize(&Bcast {
            Gamma_i_commit,
            k_i_ciphertext,
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r2::R2 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                gamma_i,
                Gamma_i,
                Gamma_i_reveal,
                w_i,
                k_i,
                k_i_randomness,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            p2ps_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::R1;
    use crate::{
        paillier_k256::{self, zk::range},
        refactor::{
            collections::TypedUsize,
            sign::{
                malicious::{log_confess_info, Behaviour},
                SignParticipantIndex,
            },
        },
    };

    impl R1 {
        pub fn corrupt_gamma_i(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            mut gamma_i: k256::Scalar,
        ) -> k256::Scalar {
            if let Behaviour::R1BadGammaI = self.behaviour {
                log_confess_info(me, &self.behaviour, "");
                gamma_i += k256::Scalar::one();
            }
            gamma_i
        }

        // pub fn corrupt_ek_proof(
        //     &self,
        //     my_index: TypedUsize<KeygenPartyIndex>,
        //     ek_proof: EncryptionKeyProof,
        // ) -> EncryptionKeyProof {
        //     if let Behaviour::R1BadEncryptionKeyProof = self.behaviour {
        //         info!("malicious party {} do {:?}", my_index, self.behaviour);
        //         paillier_k256::zk::malicious::corrupt_ek_proof(ek_proof)
        //     } else {
        //         ek_proof
        //     }
        // }

        pub fn corrupt_range_proof(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            recipient: TypedUsize<SignParticipantIndex>,
            range_proof: range::Proof,
        ) -> range::Proof {
            if let Behaviour::R1BadProof { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(me, &self.behaviour, "");
                    return paillier_k256::zk::range::malicious::corrupt_proof(&range_proof);
                }
            }
            range_proof
        }
    }
}
