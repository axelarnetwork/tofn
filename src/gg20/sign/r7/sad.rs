use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::paillier,
    gg20::{
        keygen::SecretKeyShare,
        sign::{r7::common::R7Path, KeygenShareIds, SignShareId},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::error;

use super::{
    super::{r1, r5, r6},
    common::check_message_types,
};

#[allow(non_snake_case)]
pub(in super::super) struct R7Sad {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: FullP2ps<SignShareId, r5::P2p>,
}

impl Executer for R7Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = r6::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        let paths = check_message_types(info, &bcasts_in, &p2ps_in, &mut faulters)?;
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // verify complaints
        for (accuser_sign_id, p2ps_option, path) in zip2(p2ps_in, paths) {
            if !matches!(path, R7Path::Sad) {
                continue;
            }
            let p2ps = p2ps_option.ok_or(TofnFatal)?;

            for (accused_sign_id, p2p) in p2ps {
                debug_assert_ne!(accused_sign_id, accuser_sign_id); // self accusation is impossible

                let zkp_complaint = match p2p {
                    r6::P2p::Sad(p2p_sad) => p2p_sad.zkp_complaint,
                    r6::P2p::SadType5(_) => return Err(TofnFatal),
                };
                if !zkp_complaint {
                    continue;
                }

                let accused_keygen_id = *self.all_keygen_ids.get(accused_sign_id)?;
                let accuser_keygen_id = *self.all_keygen_ids.get(accuser_sign_id)?;

                // check r5 range proof wc
                let accused_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accused_keygen_id)?
                    .ek();
                let accused_k_i_ciphertext = &self.r1bcasts.get(accused_sign_id)?.k_i_ciphertext;
                let accused_R_i = self.r5bcasts.get(accused_sign_id)?.R_i.as_ref();

                let accused_stmt = &paillier::zk::range::StatementWc {
                    stmt: paillier::zk::range::Statement {
                        prover_id: accused_sign_id,
                        verifier_id: accuser_sign_id,
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
                    true => {
                        log_fault_info(my_sign_id, accuser_sign_id, "false R5 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(
                            my_sign_id,
                            accused_sign_id,
                            "invalid r5 p2p range proof wc",
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        // sanity check
        if faulters.is_empty() {
            error!(
                "peer {} says: R7 failure protocol found no faulters",
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
