use ts_packet::PacketMut;

/// Wrapper around [`IntoIterator`] for a batch of packets keyed by `Key` which ensures
/// that it and all nested iterators are [`Send`].
///
/// Think of this as morally `HashMap<Key, Vec<PacketMut>>`, but with added flexibility
/// for the caller to convert source values on-the-fly without having to allocate an
/// intermediate collection.
pub trait BatchSendIter<Key>: Send {
    /// Equivalent of the `IntoIter` type with the `Send` bound applied and `Item`
    /// specified.
    type BatchIt: Iterator<Item = (Key, Self::PacketIt)> + Send;

    /// Inner packet iterator (per-`Key`).
    type PacketIt: PacketIter;

    /// Equivalent of [`IntoIterator::into_iter`], but with the bounds from `BatchIt`
    /// enforced.
    fn batch_iter(self) -> Self::BatchIt;
}

/// Wrapper around [`IntoIterator`] for a batch of packets keyed by `Key` which ensures that
/// it and the nested iterators are [`Send`].
///
/// This is used to _return_ values from [`crate::UnderlayTransport::recv`], and so has a
/// slightly different shape than [`BatchSendIter`] (the items are `Result`s).
///
/// Think of this as morally `HashMap<Key, Vec<PacketMut>>`, but with added flexibility
/// for the caller to convert source values on-the-fly without having to allocate an
/// intermediate collection.
pub trait BatchRecvIter<Key>: Send {
    /// The error type this iterator may have.
    type Error;

    /// Equivalent of the `IntoIter` type with the `Send` bound applied and `Item`
    /// specified.
    type BatchIt: Iterator<Item = Result<(Key, Self::PacketIt), Self::Error>> + Send;

    /// Inner packet iterator (per-`Key`).
    type PacketIt: PacketIter;

    /// Equivalent of [`IntoIterator::into_iter`], but with the bounds from `BatchIt`
    /// enforced.
    fn batch_iter(self) -> Self::BatchIt;
}

impl<T, Key, P> BatchSendIter<Key> for T
where
    T: IntoIterator<Item = (Key, P)> + Send,
    <T as IntoIterator>::IntoIter: Send,
    P: PacketIter,
    <P as IntoIterator>::IntoIter: Send,
{
    type BatchIt = <T as IntoIterator>::IntoIter;
    type PacketIt = P;

    fn batch_iter(self) -> Self::BatchIt {
        self.into_iter()
    }
}

impl<T, E, Key, P> BatchRecvIter<Key> for T
where
    T: IntoIterator<Item = Result<(Key, P), E>> + Send,
    <T as IntoIterator>::IntoIter: Send,
    P: PacketIter,
    <P as IntoIterator>::IntoIter: Send,
{
    type Error = E;
    type BatchIt = <T as IntoIterator>::IntoIter;
    type PacketIt = P;

    fn batch_iter(self) -> Self::BatchIt {
        self.into_iter()
    }
}

pub trait PacketIter: IntoIterator<Item = PacketMut, IntoIter = Self::PacketIt> + Send {
    type PacketIt: Send + Iterator<Item = PacketMut>;
}

impl<P> PacketIter for P
where
    P: IntoIterator<Item = PacketMut> + Send,
    <P as IntoIterator>::IntoIter: Send,
{
    type PacketIt = P::IntoIter;
}
