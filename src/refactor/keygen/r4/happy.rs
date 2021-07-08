use tracing::warn;

use crate::{
    paillier_k256,
    protocol::gg20::{GroupPublicInfo, SecretKeyShare, SharePublicInfo, ShareSecretInfo},
    refactor::{
        keygen::{r1, r2, r3, r4::sad::R4Sad, KeygenPartyIndex},
        protocol::{
            executer::{
                log_fault_warn,
                ProtocolBuilder::{self, *},
                RoundExecuter,
            },
            Fault::ProtocolFault,
        },
    },
    vecmap::{FillVecMap, Index, P2ps, VecMap},
    zkp::schnorr_k256,
};

#[cfg(feature = "malicious")]
use crate::refactor::keygen::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4 {
    pub threshold: usize,
    pub dk: paillier_k256::DecryptionKey,
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,
    pub r2bcasts: VecMap<KeygenPartyIndex, r2::Bcast>,
    pub r2p2ps: P2ps<KeygenPartyIndex, r2::P2p>,
    pub y: k256::ProjectivePoint,
    pub x_i: k256::Scalar,
    pub all_X_i: VecMap<KeygenPartyIndex, k256::ProjectivePoint>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl RoundExecuter for R4 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r3::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // move to sad path if necessary
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            warn!(
                "party {} r4 received complaints from others; move to sad path",
                index
            );
            return Box::new(R4Sad {
                r1bcasts: self.r1bcasts,
                r2bcasts: self.r2bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(party_count, index, bcasts_in, _p2ps_in);
        }

        // unwrap BcastHappy msgs
        let bcasts_in: VecMap<Self::Index, r3::BcastHappy> = bcasts_in
            .into_iter()
            .map(|(_, bcast)| match bcast {
                r3::Bcast::Happy(h) => h,
                r3::Bcast::Sad(_) => unreachable!(),
            })
            .collect();

        // verify proofs
        let mut faulters = FillVecMap::with_size(party_count);
        for (from, bcast) in bcasts_in.iter() {
            if schnorr_k256::verify(
                &schnorr_k256::Statement {
                    base: &k256::ProjectivePoint::generator(),
                    target: &self.all_X_i.get(from),
                },
                &bcast.x_i_proof,
            )
            .is_err()
            {
                log_fault_warn(index, from, "bad DL proof");
                faulters.set(from, ProtocolFault);
            }
        }
        if !faulters.is_empty() {
            return ProtocolBuilder::Done(Err(faulters));
        }

        // prepare data for final output
        let all_shares: Vec<SharePublicInfo> = self
            .r1bcasts
            .iter()
            .map(|(i, r1bcast)| SharePublicInfo {
                X_i: self.all_X_i.get(i).into(),
                ek: r1bcast.ek.clone(),
                zkp: r1bcast.zkp.clone(),
            })
            .collect();

        Done(Ok(SecretKeyShare {
            group: GroupPublicInfo {
                threshold: self.threshold,
                y: self.y.into(),
                all_shares,
            },
            share: ShareSecretInfo {
                index: index.as_usize(),
                dk: self.dk,
                x_i: self.x_i.into(),
            },
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
