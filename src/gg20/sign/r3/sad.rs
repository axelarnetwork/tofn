use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::paillier,
    gg20::{
        keygen::SecretKeyShare,
        sign::{r3::common::R3Path, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};

use tracing::error;

use super::{
    super::{r1, r2, SignShareId},
    common::check_message_types,
};

#[allow(non_snake_case)]
pub(in super::super) struct R3Sad {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r1p2ps: FullP2ps<SignShareId, r1::P2p>,
}

impl Executer for R3Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = ();
    type P2p = r2::P2p;

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
            if !matches!(path, R3Path::Sad) {
                continue;
            }
            let p2ps = p2ps_option.ok_or(TofnFatal)?;

            for (accused_sign_id, p2p) in p2ps {
                debug_assert_ne!(accused_sign_id, accuser_sign_id); // self accusation is impossible

                let zkp_complaint = match p2p {
                    r2::P2p::Sad(p2p_sad) => p2p_sad.zkp_complaint,
                    r2::P2p::Happy(_) => return Err(TofnFatal),
                };
                if !zkp_complaint {
                    continue;
                }

                let accused_keygen_id = *self.all_keygen_ids.get(accused_sign_id)?;
                let accuser_keygen_id = *self.all_keygen_ids.get(accuser_sign_id)?;

                // check r1 range proof
                let accused_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accused_keygen_id)?
                    .ek();
                let accused_k_i_ciphertext = &self.r1bcasts.get(accused_sign_id)?.k_i_ciphertext;

                let accused_stmt = &paillier::zk::range::Statement {
                    prover_id: accused_sign_id,
                    verifier_id: accuser_sign_id,
                    ciphertext: accused_k_i_ciphertext,
                    ek: accused_ek,
                };

                let accused_proof = &self
                    .r1p2ps
                    .get(accused_sign_id, accuser_sign_id)?
                    .range_proof;

                let accuser_zkp = self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(accuser_keygen_id)?
                    .zkp();

                match accuser_zkp.verify_range_proof(accused_stmt, accused_proof) {
                    true => {
                        log_fault_info(my_sign_id, accuser_sign_id, "false accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(my_sign_id, accused_sign_id, "invalid r1 p2p range proof");
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        // sanity check
        if faulters.is_empty() {
            error!("peer {} says: R3 sad path found no faulters", my_sign_id);
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
