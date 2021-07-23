use crate::{
    collections::{FillVecMap, P2ps, TypedUsize, VecMap},
    gg20::{
        crypto_tools::{hash::Randomness, paillier, vss},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sign::Participants,
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, log_fault_info, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::{ProjectivePoint, Scalar};
use tracing::error;

use super::super::{r1, r2, r3, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4 {
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
    pub k_i_randomness: paillier::Randomness,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2pHappy>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R4 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r3::happy::Bcast;

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
            .all(|(_, bcast)| matches!(bcast, r3::happy::Bcast::Happy(_)))
        {
            error!(
                "peer {} says: received no R3 complaints from others in R4 failure protocol",
                sign_id,
            );

            return Err(TofnFatal);
        }

        let accusations_iter =
            bcasts_in
                .into_iter()
                .filter_map(|(sign_peer_id, bcast)| match bcast {
                    r3::happy::Bcast::Happy(_) => None,
                    r3::happy::Bcast::Sad(accusations) => Some((sign_peer_id, accusations)),
                });

        // verify complaints
        for (accuser_sign_id, accusations) in accusations_iter {
            for (accused_sign_id, accusation) in accusations.mta_complaints.iter_some() {
                if accuser_sign_id == accused_sign_id {
                    log_fault_info(sign_id, accuser_sign_id, "self accusation");
                    faulters.set(accuser_sign_id, ProtocolFault)?;
                    continue;
                }

                let accused_keygen_id = *self.participants.get(accused_sign_id)?;
                let accuser_keygen_id = *self.participants.get(accuser_sign_id)?;

                let accuser_zkp = self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                let accuser_ek = self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .ek();

                let p2p = self.r2p2ps.get(accused_sign_id, accuser_sign_id)?;

                // check mta proofs
                let (accusation_type, result) = match *accusation {
                    r3::happy::Accusation::MtA => {
                        let accused_stmt = paillier::zk::mta::Statement {
                            ciphertext1: &self.r1bcasts.get(accuser_sign_id)?.k_i_ciphertext,
                            ciphertext2: &p2p.alpha_ciphertext,
                            ek: accuser_ek,
                        };

                        (
                            "MtA",
                            accuser_zkp.verify_mta_proof(&accused_stmt, &p2p.alpha_proof),
                        )
                    }
                    r3::happy::Accusation::MtAwc => {
                        let accused_lambda_i_S = &vss::lagrange_coefficient(
                            accused_sign_id.as_usize(),
                            &self
                                .participants
                                .iter()
                                .map(|(_, keygen_accused_id)| keygen_accused_id.as_usize())
                                .collect::<Vec<_>>(),
                        );

                        let accused_W_i = self
                            .secret_key_share
                            .group()
                            .all_shares()
                            .get(accused_keygen_id)?
                            .X_i()
                            .unwrap()
                            * accused_lambda_i_S;

                        let accused_stmt = paillier::zk::mta::StatementWc {
                            stmt: paillier::zk::mta::Statement {
                                ciphertext1: &self.r1bcasts.get(accuser_sign_id)?.k_i_ciphertext,
                                ciphertext2: &p2p.mu_ciphertext,
                                ek: accuser_ek,
                            },
                            x_g: &accused_W_i,
                        };

                        (
                            "MtAwc",
                            accuser_zkp.verify_mta_proof_wc(&accused_stmt, &p2p.mu_proof),
                        )
                    }
                };

                match result {
                    Ok(_) => {
                        log_fault_info(sign_id, accuser_sign_id, "false r2 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    Err(err) => {
                        log_fault_info(
                            sign_id,
                            accused_sign_id,
                            &format!("invalid r2 p2p {} proof because '{}'", accusation_type, err),
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
