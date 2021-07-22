use crate::{
    hash::Randomness,
    paillier_k256,
    refactor::{
        collections::{FillVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_and_p2p, log_fault_info, ProtocolBuilder, ProtocolInfo},
        },
        sign::Participants,
    },
};
use k256::{ProjectivePoint, Scalar};
use tracing::error;

use super::super::{r1, r2, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R3 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier_k256::Randomness,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r1p2ps: P2ps<SignParticipantIndex, r1::P2p>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_and_p2p::Executer for R3 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut faulters = FillVecMap::with_size(participants_count);

        // check if there are no complaints
        if bcasts_in
            .iter()
            .all(|(_, bcast)| matches!(bcast, r2::Bcast::Happy))
        {
            error!(
                "peer {} says: received no R2 complaints from others in R3 failure protocol",
                sign_id,
            );

            return Err(TofnFatal);
        }

        // TODO: do we check that P2ps are also Sad?

        let accusations_iter =
            bcasts_in
                .into_iter()
                .filter_map(|(sign_peer_id, bcast)| match bcast {
                    r2::Bcast::Happy => None,
                    r2::Bcast::Sad(accusations) => Some((sign_peer_id, accusations)),
                });

        // verify complaints
        for (accuser_sign_id, accusations) in accusations_iter {
            for accused_sign_id in accusations.zkp_complaints.iter() {
                if accuser_sign_id == accused_sign_id {
                    log_fault_info(sign_id, accuser_sign_id, "self accusation");
                    faulters.set(accuser_sign_id, ProtocolFault)?;
                    continue;
                }

                let accused_keygen_id = *self.participants.get(accused_sign_id)?;
                let accuser_keygen_id = *self.participants.get(accuser_sign_id)?;

                // check r1 range proof
                let accused_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accused_keygen_id)?
                    .ek();
                let accused_k_i_ciphertext = &self.r1bcasts.get(accused_sign_id)?.k_i_ciphertext;

                let accused_stmt = &paillier_k256::zk::range::Statement {
                    ciphertext: accused_k_i_ciphertext,
                    ek: accused_ek,
                };

                let accused_proof = &self
                    .r1p2ps
                    .get(accused_sign_id, accuser_sign_id)?
                    .range_proof;

                let accuser_zkp = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                match accuser_zkp.verify_range_proof(accused_stmt, accused_proof) {
                    Ok(_) => {
                        log_fault_info(sign_id, accuser_sign_id, "false accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    Err(err) => {
                        log_fault_info(
                            sign_id,
                            accused_sign_id,
                            &format!("invalid r1 p2p range proof because '{}'", err),
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R3 failure protocol found no faulters",
                sign_id
            );
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
