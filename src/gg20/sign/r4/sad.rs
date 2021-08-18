use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        crypto_tools::{paillier, vss},
        keygen::SecretKeyShare,
        sign::KeygenShareIds,
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};

use tracing::{error, warn};

use super::super::{r1, r2, r3, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R4Sad {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) participants: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
}

impl Executer for R4Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r3::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_share_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

        // anyone who did not send a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        let participants_count = info.total_share_count();

        // we should have received at least one complaint
        if !bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            error!(
                "peer {} says: received no R3 complaints from others in R4 failure protocol",
                my_share_id,
            );

            return Err(TofnFatal);
        }

        let accusations_iter =
            bcasts_in
                .into_iter()
                .filter_map(|(sign_peer_id, bcast)| match bcast {
                    r3::Bcast::Happy(_) => None,
                    r3::Bcast::Sad(accusations) => Some((sign_peer_id, accusations)),
                });

        // verify complaints
        for (accuser_sign_id, accusations) in accusations_iter {
            if accusations.mta_complaints.size() != participants_count {
                log_fault_info(
                    my_share_id,
                    accuser_sign_id,
                    "incorrect size of complaints vector",
                );

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            if accusations.mta_complaints.is_empty() {
                log_fault_info(my_share_id, accuser_sign_id, "no accusation found");

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            for (accused_sign_id, accusation) in accusations.mta_complaints.iter_some() {
                if accuser_sign_id == accused_sign_id {
                    log_fault_info(my_share_id, accuser_sign_id, "self accusation");
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
                    r3::Accusation::MtA => {
                        let accused_stmt = paillier::zk::mta::Statement {
                            prover_id: accused_sign_id,
                            verifier_id: accuser_sign_id,
                            ciphertext1: &self.r1bcasts.get(accuser_sign_id)?.k_i_ciphertext,
                            ciphertext2: &p2p.alpha_ciphertext,
                            ek: accuser_ek,
                        };

                        (
                            "MtA",
                            accuser_zkp.verify_mta_proof(&accused_stmt, &p2p.alpha_proof),
                        )
                    }
                    r3::Accusation::MtAwc => {
                        let accused_lambda_i_S = &vss::lagrange_coefficient(
                            accused_sign_id.as_usize(),
                            &self
                                .participants
                                .iter()
                                .map(|(_, keygen_accused_id)| keygen_accused_id.as_usize())
                                .collect::<Vec<_>>(),
                        )?;

                        let accused_W_i = self
                            .secret_key_share
                            .group()
                            .all_shares()
                            .get(accused_keygen_id)?
                            .X_i()
                            .as_ref()
                            * accused_lambda_i_S;

                        let accused_stmt = paillier::zk::mta::StatementWc {
                            stmt: paillier::zk::mta::Statement {
                                prover_id: accused_sign_id,
                                verifier_id: accuser_sign_id,
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
                    true => {
                        log_fault_info(my_share_id, accuser_sign_id, "false r2 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(
                            my_share_id,
                            accused_sign_id,
                            &format!("invalid r2 p2p {} proof", accusation_type),
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R3 failure protocol found no faulters",
                my_share_id
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
