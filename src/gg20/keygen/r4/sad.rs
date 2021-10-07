use tracing::{error, warn};

use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::keygen::{r1, r2, r3, KeygenShareId, SecretKeyShare},
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_info, Executer, ProtocolBuilder, ProtocolInfo},
    },
};

#[allow(non_snake_case)]
pub(in super::super) struct R4Sad {
    pub(in super::super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(in super::super) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<KeygenShareId, r2::P2p>,
}

impl Executer for R4Sad {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::BcastHappy;
    type P2p = r3::P2pSad;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

        // anyone who sent both bcast and p2p is a faulter
        for (peer_keygen_id, bcast_option, p2ps_option) in zip2(&bcasts_in, &p2ps_in) {
            if bcast_option.is_some() && p2ps_option.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps and bcast from peer {} in round 4 sad path",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // we should have received at least one complaint
        if !p2ps_in.iter().any(|(_, p2ps_option)| p2ps_option.is_some()) {
            error!(
                "peer {} says: received no R4 complaints in R4 sad path",
                my_keygen_id,
            );
            return Err(TofnFatal);
        }

        let accusations_iter = p2ps_in
            .into_iter()
            .filter_map(|(peer_keygen_id, p2ps_option)| {
                p2ps_option.map(|p2ps| (peer_keygen_id, p2ps))
            });

        // verify complaints
        for (accuser_keygen_id, accusations) in accusations_iter {
            // anyone who sent zero complaints is a faulter
            if accusations
                .iter()
                .all(|(_, accusation)| accusation.vss_complaint.is_none())
            {
                warn!(
                    "peer {} says: peer {} did not accuse anyone",
                    my_keygen_id, accuser_keygen_id
                );
                faulters.set(accuser_keygen_id, ProtocolFault)?;
                continue;
            }

            let accusation_iter = accusations
                .into_iter()
                .filter_map(|(accused_keygen_id, p2p)| {
                    p2p.vss_complaint.map(|c| (accused_keygen_id, c))
                });

            for (accused_keygen_id, accusation) in accusation_iter {
                debug_assert_ne!(accused_keygen_id, accuser_keygen_id); // self accusation is impossible

                let accuser_ek = &self.r1bcasts.get(accuser_keygen_id)?.ek;

                // validate randomness provided by the accuser
                if !accuser_ek.validate_randomness(&accusation.randomness) {
                    log_fault_info(my_keygen_id, accuser_keygen_id, "bad randomness");

                    faulters.set(accuser_keygen_id, ProtocolFault)?;
                    continue;
                }

                // verify encryption
                let share_ciphertext = accuser_ek.encrypt_with_randomness(
                    &accusation.share.get_scalar().into(),
                    &accusation.randomness,
                );

                if share_ciphertext
                    != self
                        .r2p2ps
                        .get(accused_keygen_id, accuser_keygen_id)?
                        .u_i_share_ciphertext
                {
                    log_fault_info(my_keygen_id, accused_keygen_id, "bad encryption");

                    faulters.set(accused_keygen_id, ProtocolFault)?;
                    continue;
                }

                // verify share commitment
                let accused_vss_commit = &self.r2bcasts.get(accused_keygen_id)?.u_i_vss_commit;
                if accused_vss_commit.validate_share(&accusation.share) {
                    log_fault_info(my_keygen_id, accuser_keygen_id, "false accusation");
                    faulters.set(accuser_keygen_id, ProtocolFault)?;
                } else {
                    log_fault_info(my_keygen_id, accused_keygen_id, "invalid vss share");
                    faulters.set(accused_keygen_id, ProtocolFault)?;
                }
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: R4 failure protocol found no faulters",
                my_keygen_id
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
