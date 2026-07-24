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
    schema::{Singleton, TableDesc},
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
            owner,
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
    owner: Owner,
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

    /// Subscribe to the whole store.
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_global(&self) -> Result<Subscription> {
        Ok(self.notifier.store.subscribe_global(self.id)?)
    }

    /// Subscribe to the singleton key/value pair `S`.
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_singleton<S: Singleton<Storage = Storage>>(&self) -> Result<Subscription> {
        Ok(self.notifier.store.subscribe::<S>(self.id)?)
    }

    /// Subscribe to the singleton key/value pair `S` and be sent its current value (if any).
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_singleton_and_notify<S: Singleton<Storage = Storage>>(
        &self,
    ) -> Result<Subscription> {
        Ok(self.notifier.store.subscribe_and_notify::<S>(self.id)?)
    }

    /// Subscribe to every key in the table `D`.
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_table<D: TableDesc<Storage = Storage>>(&self) -> Result<Subscription>
    where
        D::Key: Send,
    {
        Ok(self
            .notifier
            .store
            .table::<D>(self.owner)
            .subscribe(self.id)?)
    }

    /// Subscribe to a single `key` in the table `D`.
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_key<D: TableDesc<Storage = Storage>>(
        &self,
        key: D::Key,
    ) -> Result<Subscription>
    where
        D::Key: Send,
    {
        Ok(self
            .notifier
            .store
            .table::<D>(self.owner)
            .subscribe_key(self.id, key)?)
    }

    /// Subscribe to a single `key` in the table `D` and be sent its current value (if any).
    ///
    /// Returns [`Error::UnknownSubscriber`] if this subscriber is no longer known to the store. That
    /// will happen if the notifier cannot send notifications to this subscriber.
    pub fn subscribe_key_and_notify<D: TableDesc<Storage = Storage>>(
        &self,
        key: D::Key,
    ) -> Result<Subscription>
    where
        D::Key: Send,
    {
        Ok(self
            .notifier
            .store
            .table::<D>(self.owner)
            .subscribe_key_and_notify(self.id, key)?)
    }

    /// Remove a subscription to the whole store.
    pub fn unsubscribe_global(&self, subscription: Subscription) {
        self.notifier.store.unsubscribe_global(subscription);
    }

    /// Remove a subscription to the singleton key/value pair `S`.
    pub fn unsubscribe_singleton<S: Singleton<Storage = Storage>>(
        &self,
        subscription: Subscription,
    ) {
        self.notifier.store.unsubscribe::<S>(subscription);
    }

    /// Remove a subscription to the table `D`.
    pub fn unsubscribe_table<D: TableDesc<Storage = Storage>>(&self, subscription: Subscription) {
        self.notifier
            .store
            .table::<D>(self.owner)
            .unsubscribe(subscription);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::{sleep, timeout};
    use ts_kv_store::{Event, SingletonEvent};

    use super::*;

    ts_kv_store::store!(
        kvs: {
            Count(u64; OWNER),
        }
        tables: {
            Items(u32 => String; OWNER; notify(Clone)),
        }
    );

    const OWNER: &str = "owner";

    fn notifier() -> Arc<TokioNotifier<TableStorage>> {
        TokioNotifier::new()
    }

    fn insert_item(notifier: &TokioNotifier<TableStorage>, key: u32, value: &str) {
        notifier
            .store()
            .table::<Items>(OWNER)
            .insert(key, value.to_owned());
    }

    /// Extract the `(key, value)` of an `Items` per-key upsert, panicking on any other notification.
    fn items_key_upsert(n: &Notification) -> (u32, String) {
        match n {
            Notification::Items(Event::KeyUpsert(k, v)) => (*k, v.clone()),
            other => panic!("expected Items/KeyUpsert, got {other:?}"),
        }
    }

    /// Extract the (sorted) keys of an `Items` table-level upsert.
    fn items_table_upsert(n: &Notification) -> Vec<u32> {
        match n {
            Notification::Items(Event::TableUpsert(keys)) => {
                let mut keys = keys.clone();
                keys.sort();
                keys
            }
            other => panic!("expected Items/TableUpsert, got {other:?}"),
        }
    }

    /// Extract the value of a `Count` singleton upsert.
    fn count_upsert(n: &Notification) -> u64 {
        match n {
            Notification::Count(SingletonEvent::Upsert(v)) => *v,
            other => panic!("expected Count/Upsert, got {other:?}"),
        }
    }

    /// Wait for the next notification, panicking if none arrives.
    async fn recv_one(sub: &mut TokioSubscriber<TableStorage>) -> Notification {
        timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("timed out waiting for a notification")
            .expect("channel closed unexpectedly")
    }

    /// Assert that no notification is delivered. Gives the background task a chance to run first.
    async fn assert_idle(sub: &mut TokioSubscriber<TableStorage>) {
        match timeout(Duration::from_millis(50), sub.recv()).await {
            Err(_) => {} // nothing delivered, as expected
            Ok(Ok(n)) => panic!("expected no notification, got {n:?}"),
            Ok(Err(e)) => panic!("channel unexpectedly closed: {e:?}"),
        }
    }

    #[tokio::test]
    async fn table_subscription_receives_events() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_table::<Items>().unwrap();

        // First insert into the empty table is a table-level upsert; the next is a per-key upsert.
        insert_item(&notifier, 1, "a");
        insert_item(&notifier, 2, "b");

        assert_eq!(items_table_upsert(&recv_one(&mut sub).await), vec![1]);
        assert_eq!(
            items_key_upsert(&recv_one(&mut sub).await),
            (2, "b".to_owned())
        );
    }

    #[tokio::test]
    async fn key_subscription_filters_other_keys() {
        let notifier = notifier();
        insert_item(&notifier, 99, "x"); // seed so later inserts are per-key
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_key::<Items>(1).unwrap();

        insert_item(&notifier, 2, "two"); // a different key: filtered out
        insert_item(&notifier, 1, "one"); // the subscribed key: delivered

        assert_eq!(
            items_key_upsert(&recv_one(&mut sub).await),
            (1, "one".to_owned())
        );
        assert_idle(&mut sub).await;
    }

    #[tokio::test]
    async fn singleton_subscription_receives_updates() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_singleton::<Count>().unwrap();

        notifier.store().insert::<Count>(OWNER, 7);

        assert_eq!(count_upsert(&recv_one(&mut sub).await), 7);
    }

    #[tokio::test]
    async fn global_subscription_sees_table_and_singleton() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_global().unwrap();

        insert_item(&notifier, 1, "a");
        notifier.store().insert::<Count>(OWNER, 9);

        assert_eq!(items_table_upsert(&recv_one(&mut sub).await), vec![1]);
        assert_eq!(count_upsert(&recv_one(&mut sub).await), 9);
    }

    #[tokio::test]
    async fn subscribe_singleton_and_notify_sends_current_value() {
        let notifier = notifier();
        notifier.store().insert::<Count>(OWNER, 5); // pre-existing value, no subscribers yet
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_singleton_and_notify::<Count>().unwrap();

        assert_eq!(count_upsert(&recv_one(&mut sub).await), 5);
    }

    #[tokio::test]
    async fn subscribe_singleton_and_notify_without_value_sends_nothing() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_singleton_and_notify::<Count>().unwrap();

        assert_idle(&mut sub).await;
    }

    #[tokio::test]
    async fn subscribe_key_and_notify_sends_current_value() {
        let notifier = notifier();
        insert_item(&notifier, 1, "one"); // pre-existing value, no subscribers yet
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_key_and_notify::<Items>(1).unwrap();

        assert_eq!(
            items_key_upsert(&recv_one(&mut sub).await),
            (1, "one".to_owned())
        );
    }

    #[tokio::test]
    async fn unsubscribe_table_stops_notifications() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        let subscription = sub.subscribe_table::<Items>().unwrap();

        insert_item(&notifier, 1, "a");
        recv_one(&mut sub).await; // the subscribed update, before we unsubscribe

        sub.unsubscribe_table::<Items>(subscription);
        insert_item(&notifier, 2, "b");
        assert_idle(&mut sub).await;
    }

    #[tokio::test]
    async fn unsubscribe_global_stops_notifications() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        let subscription = sub.subscribe_global().unwrap();

        notifier.store().insert::<Count>(OWNER, 1);
        recv_one(&mut sub).await; // the subscribed update, before we unsubscribe

        sub.unsubscribe_global(subscription);
        notifier.store().insert::<Count>(OWNER, 2);
        assert_idle(&mut sub).await;
    }

    #[tokio::test]
    async fn unsubscribe_singleton_stops_notifications() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        let subscription = sub.subscribe_singleton::<Count>().unwrap();

        notifier.store().insert::<Count>(OWNER, 1);
        recv_one(&mut sub).await; // the subscribed update, before we unsubscribe

        sub.unsubscribe_singleton::<Count>(subscription);
        notifier.store().insert::<Count>(OWNER, 2);
        assert_idle(&mut sub).await;
    }

    #[tokio::test]
    async fn two_subscribers_each_receive() {
        let notifier = notifier();
        let mut a = notifier.create_subscriber(OWNER);
        let mut b = notifier.create_subscriber(OWNER);
        a.subscribe_singleton::<Count>().unwrap();
        b.subscribe_singleton::<Count>().unwrap();

        notifier.store().insert::<Count>(OWNER, 7);

        assert_eq!(count_upsert(&recv_one(&mut a).await), 7);
        assert_eq!(count_upsert(&recv_one(&mut b).await), 7);
    }

    #[tokio::test]
    async fn dropping_subscriber_removes_it_and_leaves_others_working() {
        let notifier = notifier();
        let mut kept = notifier.create_subscriber(OWNER);
        kept.subscribe_singleton::<Count>().unwrap();

        let gone = notifier.create_subscriber(OWNER);
        let gone_id = gone.id;
        gone.subscribe_singleton::<Count>().unwrap();
        assert!(notifier.senders.lock().unwrap().contains_key(&gone_id));

        drop(gone);
        // Drop removes the subscriber's sender (and forgets it in the store).
        assert!(!notifier.senders.lock().unwrap().contains_key(&gone_id));

        notifier.store().insert::<Count>(OWNER, 7);
        assert_eq!(count_upsert(&recv_one(&mut kept).await), 7);
    }

    #[tokio::test]
    async fn try_recv_reports_empty_then_buffered() {
        let notifier = notifier();
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_singleton::<Count>().unwrap();

        // Nothing published yet.
        assert_eq!(sub.try_recv().unwrap_err(), Error::ChannelEmpty);

        // Two updates are queued before we await, so the background task delivers both in one round;
        // `recv_one` proves delivery happened and takes the first, leaving the second buffered.
        notifier.store().insert::<Count>(OWNER, 1);
        notifier.store().insert::<Count>(OWNER, 2);
        assert_eq!(count_upsert(&recv_one(&mut sub).await), 1);
        assert_eq!(count_upsert(&sub.try_recv().unwrap()), 2);
        assert_eq!(sub.try_recv().unwrap_err(), Error::ChannelEmpty);
    }

    #[tokio::test(start_paused = true)]
    async fn backpressure_delivers_everything_in_order() {
        let notifier = notifier();
        insert_item(&notifier, 0, "v0"); // seed so inserts are per-key with distinct values
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_table::<Items>().unwrap();

        // Many more notifications than the (small, under-test) channel can hold at once, forcing the
        // full/requeue/retry path. Draining continuously resets the retry counter, so none is dropped.
        let n = CHANNEL_CAPACITY as u32 * 3;
        for k in 1..=n {
            insert_item(&notifier, k, &format!("v{k}"));
        }

        for k in 1..=n {
            assert_eq!(
                items_key_upsert(&recv_one(&mut sub).await),
                (k, format!("v{k}"))
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn write_burst_does_not_drop_a_live_subscriber() {
        let notifier = notifier();
        insert_item(&notifier, 0, "v0"); // seed so inserts are per-key
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_table::<Items>().unwrap();

        // Fill the channel and keep committing without ever draining it. Yielding (rather than
        // sleeping) between commits lets the sending task run a round each time without advancing
        // the clock, so every one of these rounds finds the channel full. There are more of
        // them than MAX_RETRIES, but they all happen at the same instant, so they must count as a
        // single failure and leave the subscriber alone.
        let n = CHANNEL_CAPACITY as u32 + notify::MAX_RETRIES + 5;
        for k in 1..=n {
            insert_item(&notifier, k, &format!("v{k}"));
            tokio::task::yield_now().await;
        }

        // Still known to the store, i.e. it was not removed.
        assert!(sub.subscribe_global().is_ok());

        // And still receiving: the notifications buffered before the channel filled are intact.
        assert_eq!(
            items_key_upsert(&recv_one(&mut sub).await),
            (1, "v1".into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_subscriber_is_dropped_and_cannot_resubscribe() {
        let notifier = notifier();
        insert_item(&notifier, 0, "v0"); // seed so inserts are per-key
        let mut sub = notifier.create_subscriber(OWNER);
        sub.subscribe_table::<Items>().unwrap();

        // Never drained: fill the channel and keep it full across every retry round.
        let n = CHANNEL_CAPACITY as u32 + 1;
        for k in 1..=n {
            insert_item(&notifier, k, &format!("v{k}"));
        }

        // Advance past all the retry rounds; the notifier gives up and removes the subscriber.
        sleep(notify::RETRY_TIME * (notify::MAX_RETRIES + 2)).await;

        // Regression for the previously-panicking case: subscribing on a given-up subscriber errors.
        assert_eq!(sub.subscribe_global(), Err(Error::UnknownSubscriber));

        // Its channel is closed: the already-buffered notifications drain, then it reports closure.
        let mut drained = 0;
        loop {
            match sub.try_recv() {
                Ok(_) => drained += 1,
                Err(Error::ChannelDisconnected) => break,
                Err(Error::ChannelEmpty) => {
                    panic!("channel still open: subscriber was not dropped")
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(drained, CHANNEL_CAPACITY);
    }
}
