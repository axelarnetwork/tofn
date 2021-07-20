use crate::{
    hash, paillier_k256,
    refactor::{
        keygen::SecretKeyShare,
        sdk::{
            api::{BytesVec, TofnResult},
            implementer_api::no_messages,
            ProtocolInfo,
        },
    },
};
use serde::{Deserialize, Serialize};

use super::{ParticipantsList, SignParticipantIndex, SignProtocolBuilder};

#[allow(non_snake_case)]
pub struct R1 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: k256::Scalar,
    pub participants: ParticipantsList,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i_commit_k256: hash::Output,
    pub k_i_ciphertext_k256: paillier_k256::Ciphertext,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof_k256: paillier_k256::zk::range::Proof,
}

impl no_messages::Executer for R1 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;

    fn execute(
        self: Box<Self>,
        _info: &ProtocolInfo<Self::Index>,
    ) -> TofnResult<SignProtocolBuilder> {
        todo!()
    }
}
