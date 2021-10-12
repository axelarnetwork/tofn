use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::{paillier, vss},
    gg20::{keygen::SecretKeyShare, sign::KeygenShareIds},
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
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
}

impl Executer for R4Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r3::BcastHappy;
    type P2p = r3::P2pSad;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who sent both bcast and p2p is a faulter
        for (peer_sign_id, bcast_option, p2ps_option) in zip2(&bcasts_in, &p2ps_in) {
            if bcast_option.is_some() && p2ps_option.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps and bcast from peer {} in round 4 sad path",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // we should have received at least one complaint
        if !p2ps_in.iter().any(|(_, p2ps_option)| p2ps_option.is_some()) {
            error!(
                "peer {} says: received no R3 complaints from others in R4 sad path",
                my_sign_id,
            );
            return Err(TofnFatal);
        }

        let accusations_iter = p2ps_in
            .into_iter()
            .filter_map(|(peer_sign_id, p2ps_option)| p2ps_option.map(|p2ps| (peer_sign_id, p2ps)));

        // verify complaints
        for (accuser_sign_id, accusations) in accusations_iter {
            // anyone who sent zero complaints is a faulter
            if accusations
                .iter()
                .all(|(_, accusation)| accusation.mta_complaint == r3::Accusation::None)
            {
                warn!(
                    "peer {} says: peer {} did not accuse anyone",
                    my_sign_id, accuser_sign_id
                );
                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            for (accused_sign_id, accusation) in accusations {
                debug_assert_ne!(accused_sign_id, accuser_sign_id); // self accusation is impossible

                let accused_keygen_id = *self.all_keygen_ids.get(accused_sign_id)?;
                let accuser_keygen_id = *self.all_keygen_ids.get(accuser_sign_id)?;

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
                let (log_msg, correct_proof) = match accusation.mta_complaint {
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
                                .all_keygen_ids
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
                    r3::Accusation::None => continue,
                };

                match correct_proof {
                    true => {
                        log_fault_info(my_sign_id, accuser_sign_id, "false r2 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(
                            my_sign_id,
                            accused_sign_id,
                            &format!("invalid r2 p2p {} proof", log_msg),
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R3 failure protocol found no faulters",
                my_sign_id
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
