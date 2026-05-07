use core::marker::PhantomData;

use crate::{BatchRecvIter, BatchSendIter, UnderlayTransport};

/// Trait providing key lookup from one type to another.
pub trait PeerLookup<From, To> {
    /// Lookup the corresponding `To` key from this `From` key.
    fn lookup_key(&self, from: From) -> Option<To>;
}

/// An [`UnderlayTransport`] that converts keys between two types using a [`PeerLookup`].
pub struct MapPeerKey<Inner, Lookup, DstKey> {
    inner: Inner,
    lookup: Lookup,
    dst: PhantomData<DstKey>,
}

impl<T, Lookup, DstKey> MapPeerKey<T, Lookup, DstKey> {
    /// Construct a new [`MapPeerKey`] with the given lookup.
    pub const fn new(t: T, lookup: Lookup) -> Self {
        Self {
            inner: t,
            lookup,
            dst: PhantomData,
        }
    }
}

impl<Inner, Lookup, DstKey> UnderlayTransport for MapPeerKey<Inner, Lookup, DstKey>
where
    Inner: UnderlayTransport + Send + Sync,
    Lookup: PeerLookup<Inner::PeerKey, DstKey> + PeerLookup<DstKey, Inner::PeerKey> + Send + Sync,
    DstKey: Send + Sync + 'static,
{
    type PeerKey = DstKey;
    type Error = Inner::Error;

    async fn send(&self, packet_batch: impl BatchSendIter<DstKey>) -> Result<(), Self::Error> {
        self.inner
            .send(packet_batch.batch_iter().filter_map(|(key, packets)| {
                let k = self.lookup.lookup_key(key)?;
                Some((k, packets))
            }))
            .await
    }

    async fn recv(&self) -> impl BatchRecvIter<DstKey, Error = Self::Error> {
        self.inner
            .recv()
            .await
            .batch_iter()
            .filter_map(|result| match result {
                Ok((key, pkts)) => {
                    let k = self.lookup.lookup_key(key)?;
                    Some(Ok((k, pkts)))
                }
                Err(e) => Some(Err(e)),
            })
    }
}
