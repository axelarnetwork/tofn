use tracing::warn;

use crate::{
    paillier_k256,
    protocol::gg20::{GroupPublicInfo, SecretKeyShare, SharePublicInfo, ShareSecretInfo},
    refactor::protocol::executer::{
        ProtocolBuilder::{self, *},
        RoundExecuter,
    },
    vecmap::{HoleVecMap, Index, VecMap},
    zkp::schnorr_k256,
};

use super::{r1, r3, Crime, KeygenOutput, KeygenPartyIndex};

#[allow(non_snake_case)]
pub(super) struct R4 {
    pub(super) threshold: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) r1bcasts: Vec<r1::Bcast>,
    pub(super) y: k256::ProjectivePoint,
    pub(super) x_i: k256::Scalar,
    pub(super) all_X_i: Vec<k256::ProjectivePoint>,
}

impl RoundExecuter for R4 {
    type FinalOutput = KeygenOutput;
    type Index = KeygenPartyIndex;
    type Bcast = r3::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        _party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: VecMap<Self::Index, HoleVecMap<Self::Index, Self::P2p>>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // verify proofs
        let criminals: Vec<Vec<Crime>> = bcasts_in
            .iter()
            .map(|(i, r3bcast)| {
                if schnorr_k256::verify(
                    &schnorr_k256::Statement {
                        base: &k256::ProjectivePoint::generator(),
                        target: &self.all_X_i[i.as_usize()],
                    },
                    &r3bcast.x_i_proof,
                )
                .is_err()
                {
                    let crime = Crime::R4BadDLProof;
                    warn!("party {} detect {:?} by {}", index, crime, i);
                    vec![crime]
                } else {
                    vec![]
                }
            })
            .collect();
        if !criminals.iter().all(Vec::is_empty) {
            return Done(Err(criminals));
        }

        // prepare data for final output
        let all_shares: Vec<SharePublicInfo> = self
            .r1bcasts
            .iter()
            .enumerate()
            .map(|(i, r1bcast)| SharePublicInfo {
                X_i: self.all_X_i[i].into(),
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
