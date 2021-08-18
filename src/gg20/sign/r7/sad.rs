use crate::{
    collections::{FillVecMap, P2ps, VecMap, XP2ps},
    gg20::{
        crypto_tools::paillier,
        keygen::SecretKeyShare,
        sign::{Participants, SignShareId},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::{error, warn};

use super::super::{r1, r5, r6};

#[allow(non_snake_case)]
pub(in super::super) struct R7Sad {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) participants: Participants,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: P2ps<SignShareId, r5::P2p>,
}

impl Executer for R7Sad {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_share_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

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

        let participants_count = info.share_count();

        // we should have received at least one complaint
        if !bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r6::Bcast::Sad(_)))
        {
            error!(
                "peer {} says: received no R6 complaints from others while in sad path",
                my_share_id,
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
            if accusations.zkp_complaints.max_size() != participants_count {
                log_fault_info(
                    my_share_id,
                    accuser_sign_id,
                    "incorrect size of complaints vector",
                );

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            if accusations.zkp_complaints.is_empty() {
                log_fault_info(my_share_id, accuser_sign_id, "no accusation found");

                faulters.set(accuser_sign_id, ProtocolFault)?;
                continue;
            }

            for accused_sign_id in accusations.zkp_complaints.iter() {
                if accuser_sign_id == accused_sign_id {
                    log_fault_info(my_share_id, accuser_sign_id, "self accusation");

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
                let accused_R_i = self.r5bcasts.get(accused_sign_id)?.R_i.as_ref();

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
                    true => {
                        log_fault_info(my_share_id, accuser_sign_id, "false R5 p2p accusation");
                        faulters.set(accuser_sign_id, ProtocolFault)?;
                    }
                    false => {
                        log_fault_info(
                            my_share_id,
                            accused_sign_id,
                            "invalid r5 p2p range proof wc",
                        );
                        faulters.set(accused_sign_id, ProtocolFault)?;
                    }
                };
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R7 failure protocol found no faulters",
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
