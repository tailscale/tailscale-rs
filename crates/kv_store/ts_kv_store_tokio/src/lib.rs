//! # ts_kv_store_tokio
//!
//! Tokio integration for [`ts_kv_store`] notifications. Notifications are delivered via Tokio
//! channels (though this isn't part of the API).
//!
//! A KV store is declared in the usual way using the `schema` macros. An instance of the store is
//! created as part of creating a [`TokioNotifier`]. The notifier can be used to access the store
//! (using the [`TokioNotifier::store`] method). Users should use the subscribe/unsubscribe methods
//! of the notifier, rather than the underlying store.
//!
//! A [`TokioSubscriber`] is created from a [`TokioNotifier`] and combines a subscriber identity
//! with the receiving end of a channel for receiving notifications (all subscriptions for a single
//! subscriber are sent via the same channel).

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, Weak},
};

use tokio::{
    sync::{
        Notify,
        mpsc::{Receiver, Sender, channel, error::TryRecvError},
    },
    task::JoinHandle,
};
use ts_kv_store::{
    GeneratedStorage, KvStore, Notifications, Notifier, Owner, Subscriber, Subscription,
};

mod notify;

/// The capacity of each subscriber's notification channel.
#[cfg(not(test))]
const CHANNEL_CAPACITY: usize = 32;
#[cfg(test)]
const CHANNEL_CAPACITY: usize = 2;

/// A [`Notifier`] which forwards notifications to subscribers using Tokio channels.
///
/// The generic parameter `Storage` links a notifier instance to a specific store.
pub struct TokioNotifier<Storage: GeneratedStorage> {
    store: Arc<KvStore<Storage>>,
    senders: Mutex<HashMap<Subscriber, SubscriberSender<Storage>>>,
    /// Notifications waiting to be sent, oldest first.
    queue: Mutex<VecDeque<QueuedNotifications<Storage>>>,
    /// Signalled whenever `queue` is added to, to wake `task`.
    notify: Arc<Notify>,
    /// Async task which sends queued notifications to subscribers.
    task: JoinHandle<()>,
}

/// The notifications from a single transaction, as queued for sending.
///
/// This is a [`Notifications`] in its map form.
type QueuedNotifications<Storage> =
    HashMap<Subscription, Vec<<Storage as GeneratedStorage>::Notification>>;

impl<Storage: GeneratedStorage + 'static> TokioNotifier<Storage> {
    /// Create a new `TokioNotifier` and [`KvStore`]. Spawns a task to send notifcations.
    ///
    /// The notifier owns the store and the store holds a weak reference back to the notifier.
    ///
    /// Spawns the task which sends notifications to subscribers, so this must be called from within
    /// a Tokio runtime. The task runs until the notifier is dropped, waking whenever there are
    /// notifications to send and periodically while any are waiting to be retried.
    pub fn new() -> Arc<TokioNotifier<Storage>> {
        let notify = Arc::new(Notify::new());

        Arc::new_cyclic(|weak: &Weak<TokioNotifier<Storage>>| {
            let task = tokio::spawn(notify::notify_loop(weak.clone(), notify.clone()));

            TokioNotifier {
                store: Arc::new(KvStore::from_notifier(weak.clone())),
                senders: Default::default(),
                queue: Default::default(),
                notify,
                task,
            }
        })
    }

    /// The [`KvStore`] this notifier was created for.
    pub fn store(&self) -> &Arc<KvStore<Storage>> {
        &self.store
    }

    /// Create a new subscriber to this notifier.
    pub fn create_subscriber(self: &Arc<Self>, owner: Owner) -> TokioSubscriber<Storage> {
        let id = self.store.register_subscriber(owner);
        let (sender, receiver) = channel(CHANNEL_CAPACITY);

        self.senders
            .lock()
            .unwrap()
            .insert(id, SubscriberSender::new(sender));

        TokioSubscriber {
            id,
            receiver,
            notifier: self.clone(),
            _owner: owner,
        }
    }

    fn remove_subscriber(&self, subscriber: Subscriber) {
        self.senders.lock().unwrap().remove(&subscriber);
        self.store.remove_subscriber(subscriber);
    }
}

impl<Storage: GeneratedStorage> fmt::Debug for TokioNotifier<Storage> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TokioNotifier").finish()
    }
}

impl<Storage: GeneratedStorage + 'static> Notifier for TokioNotifier<Storage> {
    type Notification = Storage::Notification;

    fn notify(&self, notifications: Notifications<Self::Notification>) {
        self.queue.lock().unwrap().push_back(notifications.into());
        self.notify.notify_one();
    }
}

impl<Storage: GeneratedStorage> Drop for TokioNotifier<Storage> {
    fn drop(&mut self) {
        // Stop the sending task. Without this, the task would wait forever.
        self.task.abort();
    }
}

/// A subscriber to a [`KvStore`]'s notifications, via [`TokioNotifier`]. Identifies a subscriber
/// and receives notifications.
///
/// Dropping a subscriber removes it and all its subscriptions from the store.
pub struct TokioSubscriber<Storage: GeneratedStorage + 'static> {
    /// KvStore's id for this subscriber.
    id: Subscriber,
    /// Reference to our 'parent' notifier.
    notifier: Arc<TokioNotifier<Storage>>,
    /// Receiver end of a Tokio channel for receiving notifications from the notifier.
    receiver: Receiver<Storage::Notification>,
    _owner: Owner,
}

impl<Storage: GeneratedStorage + 'static> TokioSubscriber<Storage> {
    /// Wait for the next notification.
    ///
    /// Returns [`Error::ChannelDisconnected`] if the channel is closed. No further notifications will
    /// arrive after that.
    pub async fn recv(&mut self) -> Result<Storage::Notification> {
        self.receiver.recv().await.ok_or(Error::ChannelDisconnected)
    }

    /// Receive the next notification without waiting.
    ///
    /// Returns [`Error::ChannelEmpty`] if there is no notification to receive, or [`Error::ChannelDisconnected`] if the
    /// channel is closed (see [`recv`](Self::recv)).
    pub fn try_recv(&mut self) -> Result<Storage::Notification> {
        self.receiver.try_recv().map_err(|e| match e {
            TryRecvError::Empty => Error::ChannelEmpty,
            TryRecvError::Disconnected => Error::ChannelDisconnected,
        })
    }
}

impl<Storage: GeneratedStorage + 'static> Drop for TokioSubscriber<Storage> {
    /// Remove the subscriber (and thus all its subscriptions) from the store, drop the notifier's
    /// sender for it, and close its channel.
    fn drop(&mut self) {
        self.notifier.remove_subscriber(self.id);
    }
}

/// A subscriber's channel, and how it is doing at receiving notifications.
struct SubscriberSender<Storage: GeneratedStorage> {
    sender: Sender<Storage::Notification>,
    /// `None` if the last send to this subscriber succeeded, otherwise how close we are to giving
    /// up on it.
    failing: Option<notify::Failing>,
}

impl<Storage: GeneratedStorage> SubscriberSender<Storage> {
    fn new(sender: Sender<Storage::Notification>) -> Self {
        SubscriberSender {
            sender,
            failing: None,
        }
    }
}

/// Errors due to the notifier or the store.
///
/// Subsumes [`ts_kv_store::Error`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The subscriber is not (or no longer) known to the store.
    #[error("Unknown subscriber")]
    UnknownSubscriber,
    /// An attempt was made to subscribe to the store, but the store has no notifier, so subscriptions
    /// would not be sent. This is likely because there is a reference to the store but not the notifier,
    /// so the notifier has been dropped.
    #[error("Store has no registered notifer")]
    MissingNotifier,
    /// A non-blocking [`TokioSubscriber::try_recv`] found no notification waiting.
    #[error("No notifications in channel")]
    ChannelEmpty,
    /// The subscriber's notification channel is closed, so no more notifications will ever arrive.
    #[error("Notification channel is closed")]
    ChannelDisconnected,
}

impl From<ts_kv_store::Error> for Error {
    fn from(e: ts_kv_store::Error) -> Self {
        match e {
            ts_kv_store::Error::UnknownSubscriber => Error::UnknownSubscriber,
            ts_kv_store::Error::MissingNotifier => Error::MissingNotifier,
            _ => unreachable!(),
        }
    }
}

/// A `Result` whose error is this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
