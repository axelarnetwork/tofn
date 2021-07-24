use crate::{
    collections::{FillVecMap, P2ps, TypedUsize, VecMap},
    gg20::{
        crypto_tools::{hash::Randomness, paillier},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r4, Participants, SignShareId},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, log_fault_info, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::{ProjectivePoint, Scalar};
use tracing::error;

use super::super::{r1, r2, r3, r5, r6, Peers, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R7 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenShareId>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub r3bcasts: VecMap<SignShareId, r3::happy::BcastHappy>,
    pub r4bcasts: VecMap<SignShareId, r4::happy::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub r5p2ps: P2ps<SignShareId, r5::P2p>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R7 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut faulters = FillVecMap::with_size(participants_count);

        // check if there are no complaints
        if bcasts_in
            .iter()
            .all(|(_, bcast)| !matches!(bcast, r6::Bcast::Sad(_)))
        {
            error!(
                "peer {} says: received no R6 complaints from others while in sad path",
                sign_id,
            );

            return Err(TofnFatal);
        }

        // We prioritize complaints over type 5 faults and happy bcasts, so ignore those
        let accusations_iter =
            bcasts_in
                .into_iter()
                .filter_map(|(sign_peer_id, bcast)| match bcast {
                    r6::Bcast::Sad(accusations) => Some((sign_peer_id, accusations)),
                    _ => None,
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

                // check r5 range proof wc
                let accused_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accused_keygen_id)?
                    .ek();
                let accused_k_i_ciphertext = &self.r1bcasts.get(accused_sign_id)?.k_i_ciphertext;
                let accused_R_i = self.r5bcasts.get(accused_sign_id)?.R_i.unwrap();

                let accused_stmt = &paillier::zk::range::StatementWc {
                    stmt: paillier::zk::range::Statement {
                        ciphertext: accused_k_i_ciphertext,
                        ek: accused_ek,
                    },
                    msg_g: accused_R_i,
                    g: &self.R,
                };

                let accused_proof = &self
                    .r5p2ps
                    .get(accused_sign_id, accuser_sign_id)?
                    .k_i_range_proof_wc;

                let accuser_zkp = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                match accuser_zkp.verify_range_proof_wc(accused_stmt, accused_proof) {
                    Ok(_) => {
                        log_fault_info(sign_id, accuser_sign_id, "false R5 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    Err(err) => {
                        log_fault_info(
                            sign_id,
                            accused_sign_id,
                            &format!("invalid r5 p2p range proof wc because '{}'", err),
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R7 failure protocol found no faulters",
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
