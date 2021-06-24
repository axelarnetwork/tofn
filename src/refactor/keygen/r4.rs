use tracing::warn;

use crate::{
    fillvec::FillVec,
    paillier_k256,
    protocol::gg20::{
        keygen::crimes::Crime, GroupPublicInfo, SecretKeyShare, SharePublicInfo, ShareSecretInfo,
    },
    refactor::protocol::protocol::{Protocol, RoundExecuter},
    zkp::schnorr_k256,
};

use super::{r1, r3, KeygenOutput};

#[allow(non_snake_case)]
pub(super) struct R4 {
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) r1bcasts: Vec<r1::Bcast>,
    pub(super) y: k256::ProjectivePoint,
    pub(super) x_i: k256::Scalar,
    pub(super) all_X_i: Vec<k256::ProjectivePoint>,
}

impl RoundExecuter for R4 {
    type FinalOutput = KeygenOutput;

    fn execute(
        self: Box<Self>,
        bcasts_in: FillVec<Vec<u8>>,
        _p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> Protocol<Self::FinalOutput> {
        // deserialize incoming messages
        let r3bcasts: Vec<r3::Bcast> = bcasts_in
            .vec_ref()
            .iter()
            .map(|bytes| bincode::deserialize(&bytes.as_ref().unwrap()).unwrap())
            .collect();

        // verify proofs
        let criminals: Vec<Vec<Crime>> = r3bcasts
            .iter()
            .enumerate()
            .map(|(i, r3bcast)| {
                if schnorr_k256::verify(
                    &schnorr_k256::Statement {
                        base: &k256::ProjectivePoint::generator(),
                        target: &self.all_X_i[i],
                    },
                    &r3bcast.x_i_proof,
                )
                .is_err()
                {
                    let crime = Crime::R4BadDLProof;
                    warn!("party {} detect {:?} by {}", self.index, crime, i);
                    vec![crime]
                } else {
                    vec![]
                }
            })
            .collect();
        if !criminals.iter().all(Vec::is_empty) {
            return Protocol::Done(Err(criminals));
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

        Protocol::Done(Ok(SecretKeyShare {
            group: GroupPublicInfo {
                threshold: self.threshold,
                y: self.y.into(),
                all_shares,
            },
            share: ShareSecretInfo {
                index: self.index,
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
