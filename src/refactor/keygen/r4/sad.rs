use tracing::error;

use crate::{
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{r3, KeygenPartyIndex},
        protocol::executer::{
            ProtocolBuilder::{self, *},
            RoundExecuter,
        },
    },
    vecmap::{FillVecMap, Index, P2ps, VecMap},
};

#[cfg(feature = "malicious")]
use crate::refactor::keygen::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4Sad {
    // pub threshold: usize,
    // pub dk: paillier_k256::DecryptionKey,
    // pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,
    // pub y: k256::ProjectivePoint,
    // pub x_i: k256::Scalar,
    // pub all_X_i: VecMap<KeygenPartyIndex, k256::ProjectivePoint>,
    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl RoundExecuter for R4Sad {
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
        // extract complaints
        let bcasts_in: Vec<(Index<Self::Index>, r3::BcastSad)> = bcasts_in
            .into_iter()
            .filter_map(|(i, bcast)| {
                if let r3::Bcast::Sad(sad) = bcast {
                    Some((i, sad))
                } else {
                    None
                }
            })
            .collect();
        if bcasts_in.is_empty() {
            error!("party {} entered r4 sad path with no complaints", index);
            return Done(Err(FillVecMap::with_size(party_count)));
        }

        // verify complaints
        todo!()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
