//! # ts_kv_store_kameo
//!
//! Kameo integration for [`ts_kv_store`] notifications.

use std::sync::Arc;

use futures::StreamExt;
use kameo::{
    actor::ActorRef,
    message::{Message as KameoMessage, StreamMessage},
};
use ts_kv_store::{GeneratedStorage, GeneratedStore, Owner, schema::PrimaryTableDesc};
use ts_kv_store_tokio::TokioNotifier;

/// A `ts_kv_store` notifier which notifies via messages to Kameo actors.
pub struct Notifier<Store: GeneratedStore> {
    notifier: Arc<TokioNotifier<Store>>,
}

impl<Store: GeneratedStore> Clone for Notifier<Store> {
    fn clone(&self) -> Self {
        Notifier {
            notifier: self.notifier.clone(),
        }
    }
}

impl<Store: GeneratedStore> Default for Notifier<Store> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Store: GeneratedStore> Notifier<Store> {
    /// Create a new `Notifier` wrapped around a new [`ts_kv_store_tokio::TokioNotifier`].
    ///
    /// Spawns the task which sends notifications to subscribers, so this must be called from within
    /// a Tokio runtime. The task runs until the notifier is dropped, waking whenever there are
    /// notifications to send and periodically while any are waiting to be retried.
    pub fn new() -> Self {
        Notifier {
            notifier: TokioNotifier::new(),
        }
    }

    /// The [`KvStore`](ts_kv_store::KvStore) this notifier was created for.
    pub fn store(&self) -> &Arc<Store> {
        self.notifier.store()
    }

    /// Subscribe to changes in the kv store and deliver them as Kameo messages.
    ///
    /// Subscribes `actor` to the whole table described by `D`.
    pub fn subscribe_and_notify<D: TableBound<Store>>(
        &self,
        actor: &ActorRef<impl MessageBound<Notification<Store>>>,
        owner: Owner,
    ) {
        let subscriber = self.notifier.create_subscriber(owner);
        self.store()
            .subscribe_table_and_notify::<D>(&subscriber)
            .unwrap();
        let notifications = futures::stream::unfold(subscriber, async move |mut s| {
            s.recv().await.ok().map(|n| (n, s))
        });
        actor.attach_stream(notifications.boxed(), (), ());
    }
}

/// Describer for a table in the kv store `Store`.
///
/// Convenience trait to hide some kv store internals.
pub trait TableBound<Store: GeneratedStore>:
    PrimaryTableDesc<Storage = <Store as GeneratedStore>::Storage, Key: Send>
{
}

impl<
    Store: GeneratedStore,
    T: PrimaryTableDesc<Storage = <Store as GeneratedStore>::Storage, Key: Send>,
> TableBound<Store> for T
{
}

/// A Kameo message used to deliver a batch of notifications with type `N`.
pub type Message<N> = StreamMessage<Vec<N>, (), ()>;

/// Kameo's `Message` trait specialized to [`Message`].
pub trait MessageBound<N: Send + 'static>: KameoMessage<Message<N>> {}

impl<N: Send + 'static, T: KameoMessage<Message<N>>> MessageBound<N> for T {}

type Notification<Store> = <<Store as GeneratedStore>::Storage as GeneratedStorage>::Notification;
