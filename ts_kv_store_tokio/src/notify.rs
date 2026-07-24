//! Internal logic for sending notifications.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    sync::{Notify, mpsc::error::TrySendError},
    time::{Instant, timeout},
};
use ts_kv_store::{GeneratedStorage, Subscriber};

use crate::{QueuedNotifications, SubscriberSender, TokioNotifier};

/// How long to wait before re-sending notifications.
#[cfg(not(test))]
const RETRY_TIME: Duration = Duration::from_millis(100);
#[cfg(test)]
pub const RETRY_TIME: Duration = Duration::from_millis(5);

/// How many times to try re-sending notifications.
///
/// Only failures at least [`RETRY_TIME`] apart count towards this, so giving up on a subscriber
/// takes at least `RETRY_TIME * (MAX_RETRIES - 1)`, however often we retry in the meantime.
///
/// This is reset with a successful send. If a receiver is receiving notifications, but handling
/// them more slowly than they are being generated, the notifiers internal queue can grow without
/// bound.
#[cfg(not(test))]
const MAX_RETRIES: u32 = 10;
#[cfg(test)]
pub const MAX_RETRIES: u32 = 3;

/// Wakes up when notified and sends any queued notifications.
pub(super) async fn notify_loop<Storage: GeneratedStorage + 'static>(
    notifier: Weak<TokioNotifier<Storage>>,
    notify: Arc<Notify>,
) {
    // Don't start looping until the first time we're notified. This means that we won't try
    // and upgrade the notifier to a strong reference before the notifier is constructed.
    notify.notified().await;

    loop {
        let retry = if let Some(notifier) = notifier.upgrade() {
            notifier.send_notifications()
        } else {
            // The notifier is gone, so there is nothing left to send.
            return;
        };

        if retry {
            // Retry when the timeout expires, or sooner if we are notified.
            let _ = timeout(RETRY_TIME, notify.notified()).await;
        } else {
            notify.notified().await;
        }
    }
}

/// How close we are to removing a subscriber which is not taking its notifications.
pub(super) struct Failing {
    /// How many more failures this subscriber gets before we remove it. Counts down from
    /// `MAX_RETRIES`.
    retries_left: u32,
    /// When we last counted a failure. Failures less than `RETRY_TIME` after this one don't count: a
    /// commit wakes the sending task early, so a writer committing in a tight loop makes us retry
    /// many times in an instant, and that must not use up the retries of a subscriber which is
    /// merely waiting to be polled.
    last_failure: Instant,
}

impl<Storage: GeneratedStorage + 'static> TokioNotifier<Storage> {
    /// Send every queued notification to its subscriber's channel, returning whether this round of
    /// notifications should be retried.
    ///
    /// Notifications are discarded if their subscriber's channel is closed or missing, and re-queued
    /// if it is full. A subscriber which we fail to send anything to for [`MAX_RETRIES`] rounds is
    /// given up on: its notifications are discarded and it is removed from the notifier and the store.
    fn send_notifications(&self) -> bool {
        let round = SendRound::send_all(
            &mut self.senders.lock().unwrap(),
            std::mem::take(&mut *self.queue.lock().unwrap()),
        );

        for subscriber in round.to_remove {
            self.remove_subscriber(subscriber);
        }

        let retry = !round.requeue.is_empty();
        let mut queue = self.queue.lock().unwrap();
        for queued in round.requeue.into_iter().rev() {
            queue.push_front(queued);
        }
        retry
    }
}

/// A notification could not be sent to its subscriber.
enum SendError<Storage: GeneratedStorage> {
    /// The channel filled up; the field is the notifications which were not sent.
    Full(Vec<Storage::Notification>),
    /// The subscriber has not taken a notification for [`MAX_RETRIES`] rounds or the channel is
    /// closed.
    Dead,
}

impl<Storage: GeneratedStorage> SubscriberSender<Storage> {
    /// Record a failure to send to this subscriber, giving up on it (by returning
    /// [`SendError::Dead`]) once it has used up all [`MAX_RETRIES`] of its retries.
    ///
    /// Only failures at least [`RETRY_TIME`] apart count, so retrying sooner is free.
    fn record_failure(&mut self) -> Result<(), SendError<Storage>> {
        let now = Instant::now();
        let counts = match &self.failing {
            Some(failing) => now.duration_since(failing.last_failure) >= RETRY_TIME,
            // The first failure since the last successful send always counts.
            None => true,
        };
        if !counts {
            return Ok(());
        }

        let failing = self.failing.get_or_insert(Failing {
            retries_left: MAX_RETRIES,
            last_failure: now,
        });
        failing.last_failure = now;
        failing.retries_left -= 1;

        if failing.retries_left == 0 {
            tracing::error!("subscriber is not receiving notifications, dropping it");
            return Err(SendError::Dead);
        }

        Ok(())
    }
}

/// Send one subscription's `notifications` to its subscriber's channel, stopping at the first one
/// which cannot be sent.
///
/// Never awaits, and never blocks on a full channel: a subscriber which is not keeping up is
/// reported as [`SendError::Full`] so that the caller can retry it later, or as
/// [`SendError::Dead`] once it has ignored us for [`MAX_RETRIES`] rounds in a row. Retrying sooner
/// than [`RETRY_TIME`] does not count towards `MAX_RETRIES`.
fn send_to_subscriber<Storage: GeneratedStorage>(
    channel: &mut SubscriberSender<Storage>,
    notifications: Vec<Storage::Notification>,
) -> Result<(), SendError<Storage>> {
    let mut notifications = notifications.into_iter();
    while let Some(notification) = notifications.next() {
        match channel.sender.try_send(notification) {
            Ok(()) => channel.failing = None,
            // Re-queue this notification and everything after it for this subscriber, rather than
            // sending later notifications out of order. Give up on a subscriber which has not taken
            // a notification for a while.
            Err(TrySendError::Full(notification)) => {
                channel.record_failure()?;

                let mut rest = vec![notification];
                rest.extend(notifications);
                return Err(SendError::Full(rest));
            }
            Err(TrySendError::Closed(_)) => return Err(SendError::Dead),
        }
    }

    Ok(())
}

/// The bookkeeping for a single round of sending.
#[derive(Default)]
struct SendRound<Storage: GeneratedStorage> {
    /// Subscribers whose remaining notifications are discarded (because the receiver is dead).
    skip: HashSet<Subscriber>,
    /// Subscribers whose remaining notifications are re-queued because their channel is full.
    full: HashSet<Subscriber>,
    /// Subscribers to remove from the store and notifier.
    to_remove: Vec<Subscriber>,
    /// Notifications to be queued for re-sending.
    requeue: VecDeque<QueuedNotifications<Storage>>,
}

impl<Storage: GeneratedStorage> SendRound<Storage> {
    fn send_all(
        senders: &mut HashMap<Subscriber, SubscriberSender<Storage>>,
        queue: VecDeque<QueuedNotifications<Storage>>,
    ) -> Self {
        let mut round = Self::default();
        for queued in queue {
            round.send_transaction(senders, queued);
        }
        round
    }

    /// Send the notifications from a single transaction.
    fn send_transaction(
        &mut self,
        senders: &mut HashMap<Subscriber, SubscriberSender<Storage>>,
        queued: QueuedNotifications<Storage>,
    ) {
        let mut leftover = HashMap::new();

        for (subscription, notifications) in queued {
            let subscriber = subscription.subscriber();
            if self.skip.contains(&subscriber) {
                continue;
            }
            if self.full.contains(&subscriber) {
                leftover.insert(subscription, notifications);
                continue;
            }

            let Some(channel) = senders.get_mut(&subscriber) else {
                // Expected when a subscriber is dropped (or given up on) while it still has
                // notifications queued.
                tracing::debug!(?subscriber, "no channel for subscriber, discarding");
                self.skip.insert(subscriber);
                self.to_remove.push(subscriber);
                continue;
            };

            match send_to_subscriber(channel, notifications) {
                Ok(()) => {}
                Err(SendError::Full(rest)) => {
                    self.full.insert(subscriber);
                    leftover.insert(subscription, rest);
                }
                Err(SendError::Dead) => {
                    self.to_remove.push(subscriber);
                    self.skip.insert(subscriber);
                }
            }
        }

        if !leftover.is_empty() {
            self.requeue.push_back(leftover);
        }
    }
}
