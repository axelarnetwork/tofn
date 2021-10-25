use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{
    collections::{FillP2ps, FillVecMap, P2ps, TypedUsize},
    sdk::{
        api::{BytesVec, Fault, TofnFatal, TofnResult},
        protocol_info::ProtocolInfo,
        wire_bytes::deserialize,
    },
};

use super::{
    protocol_builder::ProtocolBuilder,
    wire_bytes::ExpectedMsgTypes::{self, *},
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for missing messages or deserialization failure
pub trait ExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute_raw(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
        expected_msg_types: FillVecMap<Self::Index, ExpectedMsgTypes>,
        faulters: FillVecMap<Self::Index, Fault>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(ExecuterRaw) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: Executer> ExecuterRaw for T {
    type FinalOutput = T::FinalOutput;
    type Index = T::Index;

    /// Default implementation of [execute_raw] via reduction to [execute].
    /// Because [execute] is usable only in the event of zero faulters,
    /// this implementation of [execute_raw] is not robust:
    /// If there are any faulters then this implementation preemptively moves the protocol to sad path.
    ///
    /// If you are implementing a robust protocol
    /// then you need to provide your own implementation of [execute_raw]
    /// that handles faulters more intelligently.
    /// In that case you can use the helper functions [timeout_faulters], [deserialize_bcasts], [deserialize_p2ps].
    fn execute_raw(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
        expected_msg_types: FillVecMap<Self::Index, ExpectedMsgTypes>,
        mut faulters: FillVecMap<Self::Index, Fault>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        timeout_faulters(
            info.my_id(),
            &bcasts_in,
            &p2ps_in,
            &expected_msg_types,
            &mut faulters,
        )?;

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in_deserialized = deserialize_bcasts(info.my_id(), bcasts_in, &mut faulters)?;
        let p2ps_deserialized = deserialize_p2ps(info.my_id(), p2ps_in, &mut faulters)?;

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // all deserialization succeeded---remove the `Some` wrapper from deserialized bcasts, p2ps
        // TODO make deserialize_p2ps() like deserialize_bcasts() so we can delete this line
        // unfortunately that requires FillP2ps to impl FromIterator, which ain't gonna happen
        let p2ps_in = p2ps_deserialized
            .map_result(|val_option| val_option.ok_or(TofnFatal))?
            .to_p2ps()?;

        // special case: total_share_count == 1: `p2ps_in` is `[None]` by default
        let p2ps_in = if info.total_share_count() == 1
            && matches!(
                expected_msg_types
                    .get(TypedUsize::from_usize(0))?
                    .ok_or(TofnFatal)?,
                BcastAndP2p | P2pOnly
            ) {
            P2ps::new_size_1_some()
        } else {
            p2ps_in
        };

        self.execute(info, bcasts_in_deserialized, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

/// Check for missing messages (timeout fault).
/// Set `faulters` appropriately.
pub fn timeout_faulters<K>(
    my_id: TypedUsize<K>,
    bcasts_in: &FillVecMap<K, BytesVec>,
    p2ps_in: &FillP2ps<K, BytesVec>,
    expected_msg_types: &FillVecMap<K, ExpectedMsgTypes>,
    faulters: &mut FillVecMap<K, Fault>,
) -> TofnResult<()> {
    debug_assert_eq!(bcasts_in.size(), expected_msg_types.size());
    debug_assert_eq!(p2ps_in.size(), expected_msg_types.size());
    for (from, expected_msg_type) in expected_msg_types.iter() {
        // each party A has told us what to expect from A (bcast and/or p2p)
        if let Some(expected_msg_type) = expected_msg_type {
            if matches!(expected_msg_type, BcastAndP2p | BcastOnly) && bcasts_in.is_none(from)? {
                warn!(
                    "peer {} says: detected missing bcast from peer {}",
                    my_id, from
                );
                faulters.set(from, Fault::MissingMessage)?;
            }

            // if p2ps are expected from party A then _all_ p2ps from A must be present
            if matches!(expected_msg_type, BcastAndP2p | P2pOnly) && !p2ps_in.is_full_from(from)? {
                let missing_tos: Vec<TypedUsize<K>> = p2ps_in
                    .iter_from(from)?
                    .filter_map(|(peer_id, val_option)| {
                        if val_option.is_none() {
                            Some(peer_id)
                        } else {
                            None
                        }
                    })
                    .collect();
                warn!(
                    "peer {} says: detected missing p2p from peer {} to peers {:?}",
                    my_id, from, missing_tos,
                );
                faulters.set(from, Fault::MissingMessage)?;
            }
        } else {
            warn!(
                    "peer {} says: expected_msg_type not set for peer {} (this peer did not send any messages)",
                    my_id,
                    from
                );
            faulters.set(from, Fault::MissingMessage)?;
        }
    }
    Ok(())
}

/// Attempt to deserialize bcasts.
/// Set `faulters` appropriately.
pub fn deserialize_bcasts<K, Bcast>(
    my_id: TypedUsize<K>,
    bcasts_in: FillVecMap<K, BytesVec>,
    faulters: &mut FillVecMap<K, Fault>,
) -> TofnResult<FillVecMap<K, Bcast>>
where
    Bcast: DeserializeOwned,
{
    bcasts_in
        .into_iter()
        .map(|(from, bytes_option)| {
            if let Some(bytes) = bytes_option {
                if let Some(val) = deserialize(&bytes) {
                    Ok(Some(val))
                } else {
                    warn!(
                        "peer {} says: detected corrupted bcast from peer {}",
                        my_id, from
                    );
                    faulters.set(from, Fault::CorruptedMessage)?;
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
        .collect::<TofnResult<FillVecMap<K, Bcast>>>()
}

/// Attempt to deserialize p2ps.
/// Set `faulters` appropriately.
pub fn deserialize_p2ps<K, P2p>(
    my_id: TypedUsize<K>,
    p2ps_in: FillP2ps<K, BytesVec>,
    faulters: &mut FillVecMap<K, Fault>,
) -> TofnResult<FillP2ps<K, Option<P2p>>>
where
    P2p: DeserializeOwned,
{
    let p2ps_deserialized: FillP2ps<K, Option<P2p>> = p2ps_in.map(|bytes| deserialize(&bytes));

    for (from, p2ps) in p2ps_deserialized.iter() {
        for (to, p2p) in p2ps.iter() {
            if let Some(None) = p2p {
                warn!(
                    "peer {} says: detected corrupted p2p from peer {} to peer {}",
                    my_id, from, to
                );
                faulters.set(from, Fault::CorruptedMessage)?;
            }
        }
    }

    Ok(p2ps_deserialized)
}
