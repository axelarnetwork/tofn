use super::super::wire_bytes::{self, MsgType::*};
use super::*;
impl<F, K, P> Round<F, K, P> {
    pub fn new_bcast_and_p2p(
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        // validate args
        if p2ps_out.len() != info.share_info().share_count() {
            error!(
                "p2ps_out length {} differs from share_count {}",
                p2ps_out.len(),
                info.share_info().share_count()
            );
            return Err(TofnFatal);
        }

        let bcast_out = wire_bytes::wrap(bcast_out, info.share_info().share_id(), Bcast)?;
        let p2ps_out = p2ps_out.map2_result(|(to, payload)| {
            wire_bytes::wrap(payload, info.share_info().share_id(), P2p { to })
        })?;

        let len = info.share_info().share_count(); // squelch build error
        Ok(Self::new(
            info,
            RoundType::BcastAndP2p(BcastAndP2pRound {
                round,
                bcast_out,
                p2ps_out,
                bcasts_in: FillVecMap::with_size(len),
                p2ps_in: FillP2ps::with_size(len),
            }),
        ))
    }

    pub fn new_bcast_only(
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        bcast_out: BytesVec,
    ) -> TofnResult<Self> {
        let bcast_out = wire_bytes::wrap(bcast_out, info.share_info().share_id(), Bcast)?;

        let len = info.share_info().share_count(); // squelch build error
        Ok(Self::new(
            info,
            RoundType::BcastOnly(BcastOnlyRound {
                round,
                bcast_out,
                bcasts_in: FillVecMap::with_size(len),
            }),
        ))
    }

    pub fn new_p2p_only(
        round: Box<dyn p2p_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        // validate args
        if p2ps_out.len() != info.share_info().share_count() {
            error!(
                "p2ps_out length {} differs from share_count {}",
                p2ps_out.len(),
                info.share_info().share_count()
            );
            return Err(TofnFatal);
        }

        let p2ps_out = p2ps_out.map2_result(|(to, payload)| {
            wire_bytes::wrap(payload, info.share_info().share_id(), P2p { to })
        })?;

        let len = info.share_info().share_count(); // squelch build error
        Ok(Self::new(
            info,
            RoundType::P2pOnly(P2pOnlyRound {
                round,
                p2ps_out,
                p2ps_in: FillP2ps::with_size(len),
            }),
        ))
    }

    pub fn new_no_messages(
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
    ) -> TofnResult<Self> {
        Ok(Self::new(
            info,
            RoundType::NoMessages(NoMessagesRound { round }),
        ))
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => r.round.as_any(),
            RoundType::BcastOnly(r) => r.round.as_any(),
            RoundType::P2pOnly(r) => r.round.as_any(),
            RoundType::NoMessages(r) => r.round.as_any(),
        }
    }
}
