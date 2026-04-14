#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub use std::time::{Duration, Instant};
use std::{
    cmp::min,
    sync::{Arc, Mutex, Weak},
};

/// A range of time between two [`Instant`]s.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeRange {
    start: Instant,
    end: Instant,
}

impl TimeRange {
    /// Return a time range spanning from `start` to `end` inclusive.
    ///
    /// # Panics
    ///
    /// If `start > end`.
    pub fn new(start: Instant, end: Instant) -> Self {
        assert!(start <= end);
        Self { start, end }
    }

    /// Return a time range centered on `t`, with `plus_minus` time on either side.
    pub fn new_around(t: Instant, plus_minus: Duration) -> Self {
        Self::new(t - plus_minus, t + plus_minus)
    }

    /// The first [`Instant`] that the interval covers.
    pub fn start(&self) -> Instant {
        self.start
    }

    /// The last [`Instant`] that the interval covers.
    pub fn end(&self) -> Instant {
        self.end
    }

    /// Reports whether the time range contains `t`.
    ///
    /// A time range contains `t` if `self.start() <= t <= self.end()`.
    pub fn contains(&self, t: Instant) -> bool {
        t >= self.start && t <= self.end
    }
}

impl From<TimeRange> for Duration {
    fn from(t: TimeRange) -> Duration {
        t.end - t.start
    }
}

#[derive(Debug)]
struct FutureEvent<E> {
    when: TimeRange,
    what: E,
}

/// A scheduler for future events.
///
/// The scheduler does not dispatch events itself, rather it provides the facilities needed for the
/// caller to efficiently dispatch events in as few wakeups as possible.
#[derive(Debug)]
pub struct Scheduler<E> {
    // Currently scheduled timers, sorted by descending start of their time range.
    //
    // The ordering is the reverse of the intuitive one so that dispatching of events can be
    // implemented by truncating the Vec's tail.
    //
    // Invariant: each FutureEvent is referenced from a few places only: one Arc in this Vec,
    // one Weak in the Handle for the event, and a temporary upgraded Arc during the execution of
    // Handle's methods. This invariant is relied upon by SchedulerInner, which accounts for all
    // these potential references prior to unwrapping Arc::get_mut and Arc::into_inner.
    // Additional rogue references would invalidate this accounting and cause runtime panics.
    events: Arc<Mutex<Vec<Arc<FutureEvent<E>>>>>,
}

impl<E> Default for Scheduler<E> {
    fn default() -> Self {
        Self {
            events: Default::default(),
        }
    }
}

impl<E> Scheduler<E> {
    /// Returns the index of the first element of events whose start time is less than or
    /// equal to `t`, or events.len() if no such element exists.
    ///
    /// `events` must be sorted by descending event start time.
    fn partition_point(events: &[Arc<FutureEvent<E>>], t: Instant) -> usize {
        events.partition_point(|e| e.when.start > t)
    }

    fn find(events: &[Arc<FutureEvent<E>>], event: &Arc<FutureEvent<E>>) -> Option<usize> {
        let idx = Scheduler::partition_point(events, event.when.start);
        for (i, other) in events[idx..].iter().enumerate() {
            if other.when.start != event.when.start {
                return None;
            }
            if Arc::ptr_eq(event, other) {
                return Some(idx + i);
            }
        }
        None
    }

    /// Schedule an event to occur at a future point in time.
    ///
    /// Returns a [`Handle`] which may be used to cancel or reschedule the event. The caller need
    /// not retain the Handle if cancellation and rescheduling are not required.
    pub fn add(&mut self, when: TimeRange, what: E) -> Handle<E> {
        let event = Arc::new(FutureEvent { when, what });
        let weak_event = Arc::downgrade(&event);
        let mut events = self.events.lock().unwrap();
        let idx = Scheduler::partition_point(&events, when.start);
        events.insert(idx, event);
        Handle {
            events: Arc::downgrade(&self.events),
            event: weak_event,
        }
    }

    /// Cancel all pending events, leaving the scheduler idle.
    pub fn clear(&mut self) {
        self.events.lock().unwrap().clear();
    }

    /// Removes events that are due to happen at or before `now` from the scheduler's queue,
    /// returning an iterator over the removed events.
    ///
    /// If the iterator is dropped before being fully consumed, it drops the remaining removed
    /// events.
    pub fn dispatch(&mut self, now: Instant) -> impl Iterator<Item = E> + use<E> {
        let mut events = self.events.lock().unwrap();
        let idx = Scheduler::partition_point(&events, now);
        let to_dispatch = events.split_off(idx);

        // Invariant: at most 3 refs to the event exist (see doc on SchedulerInner struct).
        // We haven't upgraded the Handle's Weak, so that Arc doesn't exist. The iterator owns the
        // Arc that was formerly in self.events, and into_inner is not blocked by the existence of
        // the Handle's Weak. Thus, into_inner always succeeds.
        to_dispatch
            .into_iter()
            .rev()
            .map(|e| Arc::into_inner(e).unwrap().what)
    }

    /// Returns the next time range in which [`Scheduler::dispatch`] should next be called to
    /// dispatch events.
    ///
    /// [`Scheduler::dispatch`] should be called at some point in the returned [`TimeRange`] to
    /// dispatch events on time.
    ///
    /// Calling `dispatch` closer to the end of the range is more efficient and results in more
    /// events being available. Calling `dispatch` before the returned range is inefficient
    /// but otherwise harmless.
    ///
    /// The returned range may lie entirely in the past, if overdue events exists. The caller is
    /// expected to call [`Scheduler::dispatch`] as soon as possible in that case.
    ///
    /// This method is intended to be used to plumb this Scheduler's event dispatch into another
    /// Scheduler.
    pub fn next_dispatch_range(&self) -> Option<TimeRange> {
        let events = self.events.lock().unwrap();
        let start = events.last()?.when.start;
        let mut end = events.last()?.when.end;

        for e in events.iter().rev().skip(1) {
            if e.when.start > end {
                break;
            }
            end = min(end, e.when.end);
        }

        Some(TimeRange::new(start, end))
    }

    /// Returns the next time at which [`Scheduler::dispatch`] should next be called to dispatch
    /// events.
    ///
    /// This is the same as [`Scheduler::next_dispatch_range`], but only returns the [`Instant`]
    /// corresponding to the end of the feasible time range.
    ///
    /// Calling `dispatch` before the returned time is inefficient but otherwise harmless.
    ///
    /// The returned time may be in the past, if overdue events exists. The caller is
    /// expected to call [`Scheduler::dispatch`] as soon as possible in that case.
    ///
    /// This method is intended to be used to plumb this Scheduler into an external timer facility
    /// (e.g. `std::thread::sleep`, `tokio::time::sleep`), to trigger event dispatching at the
    /// appropriate time.
    pub fn next_dispatch(&self) -> Option<Instant> {
        Some(self.next_dispatch_range()?.end)
    }

    /// Assert that the scheduler's internal state is consistent.
    ///
    /// # Panics
    ///
    /// If the scheduler's internal invariants are violated.
    #[cfg(test)]
    fn assert_consistent(&self) {
        assert!(
            self.events
                .lock()
                .unwrap()
                .is_sorted_by(|a, b| a.when.start >= b.when.start)
        );
    }
}

/// A handle for a scheduled future event, allowing the holder to reschedule or cancel the event.
///
/// The handle may outlive the event it relates to. Calling methods on such a lapsed Handle is safe.
///
/// Handles that aren't needed for cancellation or rescheduling can be dropped without impacting
/// the related event.
pub struct Handle<E> {
    events: Weak<Mutex<Vec<Arc<FutureEvent<E>>>>>,
    event: Weak<FutureEvent<E>>,
}

impl<E> Handle<E> {
    /// Attempts to cancel the event.
    ///
    /// If the event hasn't yet occurred when cancel is called, it is canceled and will not be
    /// returned by [`Scheduler::dispatch`]. Cancelling an event that has already been dispatched
    /// is a no-op.
    pub fn cancel(self) {
        let Some(events) = self.events.upgrade() else {
            return;
        };
        let Some(event) = self.event.upgrade() else {
            return;
        };
        let mut events = events.lock().unwrap();
        let Some(idx) = Scheduler::find(&events, &event) else {
            return;
        };
        events.remove(idx);
    }

    /// Attempts to reschedule the event to a new time range.
    ///
    /// Returns an updated Handle if rescheduling succeeds, or None if the event has already
    /// been dispatched.
    pub fn reschedule(self, when: TimeRange) -> Option<Handle<E>> {
        let events = self.events.upgrade()?;
        let mut events = events.lock().unwrap();
        let mut event = self.event.upgrade()?;
        drop(self.event);
        let idx = Scheduler::find(&events, &event)?;
        drop(events.remove(idx));
        // Invariant: At most 3 refs to the event exist (see doc on SchedulerInner struct).
        // We dropped the Handle's Weak and events's Arc above, leaving `event` as the sole Arc
        // for this event. Thus, get_mut always succeeds.
        Arc::get_mut(&mut event).unwrap().when = when;
        let weak = Arc::downgrade(&event);

        let idx = Scheduler::partition_point(&events, when.start);
        events.insert(idx, event);
        drop(events);

        Some(Handle {
            events: self.events,
            event: weak,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fmt::Debug, hash::Hash};

    use super::*;

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
    enum Event {
        Foo,
        Bar(usize),
    }

    fn check_next<E: Debug + Eq + Hash>(
        sched: &mut Scheduler<E>,
        want_next: TimeRange,
        want_events: Vec<E>,
    ) {
        // Pending events are only sorted according to their range's start time, so when multiple
        // events have the same start time the exact order in which they're returned is dependent
        // on insertion order. We don't care about the relative ordering of such events, so just
        // toss everything into a set and check that the right set of events was dispatched.
        let want_events: HashSet<E> = HashSet::from_iter(want_events);

        let next = sched.next_dispatch_range();
        assert_eq!(next, Some(want_next));
        let next = sched.next_dispatch();
        assert_eq!(next, Some(want_next.end));
        let next = next.unwrap();

        let events = sched.dispatch(next).collect::<HashSet<E>>();
        assert_eq!(events, want_events);
    }

    fn check_empty<E>(sched: &mut Scheduler<E>) {
        assert_eq!(sched.next_dispatch(), None);
        assert_eq!(sched.next_dispatch_range(), None);
    }

    #[test]
    fn test_basic() {
        let datum = Instant::now();
        let mut sched = Scheduler::default();
        sched.add(TimeRange::new(datum, datum), Event::Foo);
        check_next(&mut sched, TimeRange::new(datum, datum), vec![Event::Foo]);
        check_empty(&mut sched);
    }

    #[test]
    fn test_many() {
        let datum = Instant::now();
        let mut sched = Scheduler::default();
        let ranges: Vec<(u64, u64)> = vec![(1, 9), (2, 8), (3, 7), (4, 6), (5, 5), (2, 4)];
        // Event ranges:
        //
        // <-------> (1,9)
        //  <----->  (2,8)
        //   <--->   (3,7)
        //    <->    (4,6)
        //     x     (5,5)
        //  <->      (2,4)
        //
        for (i, (start, end)) in ranges.iter().enumerate() {
            let start = datum + Duration::from_secs(*start);
            let end = datum + Duration::from_secs(*end);
            let range = TimeRange::new(start, end);
            sched.add(range, Event::Bar(i));
        }
        // First wakeup at 4, all events except (5,5).
        check_next(
            &mut sched,
            TimeRange::new(
                datum + Duration::from_secs(1),
                datum + Duration::from_secs(4),
            ),
            vec![
                Event::Bar(0),
                Event::Bar(1),
                Event::Bar(2),
                Event::Bar(3),
                Event::Bar(5),
            ],
        );
        // Final dispatch at 5, only (5,5).
        check_next(
            &mut sched,
            TimeRange::new(
                datum + Duration::from_secs(5),
                datum + Duration::from_secs(5),
            ),
            vec![Event::Bar(4)],
        );
        check_empty(&mut sched);
    }
}

#[cfg(test)]
mod proptests {
    use std::{cmp::max, fmt::Debug, sync::LazyLock};

    use proptest::{collection::vec, prelude::*};

    use super::*;

    static DATUM: LazyLock<Instant> = LazyLock::new(Instant::now);

    prop_compose! {
        fn arb_timerange()(start in 1..u16::MAX, duration in any::<u16>()) -> (Duration, Duration) {
            let start = Duration::from_millis(start as u64);
            let end = start+Duration::from_millis(duration as u64);
            (start, end)
        }
    }

    #[derive(Copy, Clone, Debug)]
    enum Action {
        /// Run a dispatch cycle, checking invariants on produced events
        Dispatch,
        /// Schedule a new event for the given time range.
        Add((Duration, Duration)),
        /// Cancel a previously added event. The f64 must be in 0..1, and is rescaled to the total
        /// number of scheduled events so far in the run, so will try to cancel a uniformly sampled
        /// prior event (which may have already been canceled).
        Cancel(f64),
        /// Reschedule a previously added event. The f64 is rescaled as with Cancel.
        Reschedule((f64, (Duration, Duration))),
    }

    /// Convert a random 0-1 float value into an index in the range 0..max.
    ///
    /// Used below to distribute cancellations and reschedules over previously created events.
    fn sample(v: f64, max: usize) -> usize {
        (max as f64 * v.clamp(0f64, 1f64)).floor() as usize
    }

    fn arb_scheduler_action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Dispatch),
            arb_timerange().prop_map(Action::Add),
            (0f64..1f64).prop_map(Action::Cancel),
            ((0f64..1f64), arb_timerange()).prop_map(Action::Reschedule),
        ]
    }

    struct Event {
        id: usize,
        range: Mutex<TimeRange>,
    }

    impl Event {
        fn new(id: usize, start: Duration, end: Duration) -> Self {
            let range = Mutex::new(TimeRange::new(*DATUM + start, *DATUM + end));
            Self { id, range }
        }

        fn update(&mut self, start: Duration, end: Duration) {
            let mut range = self.range.lock().unwrap();
            *range = TimeRange::new(*DATUM + start, *DATUM + end);
        }
    }

    impl Debug for Event {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let (start, end) = {
                let range = self.range.lock().unwrap();
                (range.start, range.end)
            };
            f.debug_struct("ReschedulableEvent")
                .field("id", &self.id)
                .field("start", &(start - *DATUM))
                .field("end", &(end - *DATUM))
                .finish()
        }
    }

    proptest! {
        #[test]
        fn test_events(times in vec(arb_timerange(), 1..100)) {
            let mut sched = Scheduler::default();
            for (start, end) in &times {
                let tr = TimeRange::new(*DATUM+*start, *DATUM+*end);
                sched.add(tr, (start, end, tr));
                sched.assert_consistent();
            }

            let mut total_seen = 0;
            let mut last_time = *DATUM;
            while let Some(next) = sched.next_dispatch() {
                // Invariant: dispatch time always moves forward.
                assert!(next > last_time, "next={:?}, last={:?}", next-*DATUM, last_time-*DATUM);
                last_time = next;

                for (start, end, tr) in sched.dispatch(next) {
                    total_seen += 1;
                    // Invariant: all events dispatch within their requested time range.
                    // Note this is only true in this test because we schedule all events upfront,
                    // all the events are scheduled for a future time.
                    assert!(tr.contains(next), "range=({:?}, {:?}), next={:?}", start, end, next-*DATUM);
                }
                sched.assert_consistent();
            }

            // Invariant: the scheduler doesn't forget events.
            assert_eq!(total_seen, times.len());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn test_event_handles(actions in vec(arb_scheduler_action(), 1..100)) {
            let mut sched: Scheduler<usize> = Scheduler::default();
            let mut events: Vec<Option<Event >> = Vec::new();
            let mut handles: Vec<Option<Handle<usize>>> = Vec::new();
            let mut now = *DATUM;
            let mut total_scheduled = 0;
            let mut total_canceled = 0;
            let mut total_dispatched = 0;
            println!("\nSTART, now=0s");
            for action in actions {
                sched.assert_consistent();
                match action {
                    Action::Dispatch => {
                        let Some(next) = sched.next_dispatch() else {
                            println!("Dispatch (no scheduled events)");
                            continue;
                        };
                        // Due to reschedules, next may be in the past.
                        now = max(next, now);
                        println!("Dispatch, now={:?}", now-*DATUM);

                        for idx in sched.dispatch(now) {
                            if let Some(event) = events[idx].take() {
                                println!("  {:?}", event);
                                total_dispatched += 1;
                                let tr = event.range.lock().unwrap();
                                // Invariant: events dispatch within their requested time range, or
                                // are being dispatched late in the case of events (re)scheduled
                                // in the past.
                                assert!(tr.contains(now) || now > tr.end());
                            } else {
                                panic!("dispatched canceled event {}", idx);
                            }
                        }
                    }
                    Action::Add((start, end)) => {
                        let val = Event::new(events.len(), start, end);
                        println!("Add {:?}", val);
                        let tr = {
                            let range = val.range.lock().unwrap();
                            *range
                        };
                        let handle = sched.add(tr, val.id);
                        events.push(Some(val));
                        handles.push(Some(handle));
                        total_scheduled += 1;
                    }
                    Action::Cancel(idx) => {
                        if events.is_empty() {
                            println!("Cancel() (no events yet)");
                            continue;
                        }
                        let idx = sample(idx, events.len());
                        if let Some(handle) = handles[idx].take() {
                            println!("Cancel({})", idx);
                            handle.cancel();
                            events[idx] = None;
                            total_canceled += 1;
                        } else {
                            println!("Cancel({}) (already canceled)", idx);
                        };
                    }
                    Action::Reschedule((idx, (start, end))) => {
                        if events.is_empty() {
                            println!("Reschedule() (no events yet)");
                            continue;
                        }
                        let idx = sample(idx, events.len());
                        if let Some(event) = &mut events[idx] {
                            event.update(start, end);
                            let tr = {
                                *event.range.lock().unwrap()
                            };
                            println!("Reschedule({}) event={:?}", idx, event);
                            handles[idx] = handles[idx].take().and_then(|handle| handle.reschedule(tr));
                        } else {
                            println!("Reschedule({}) (no such event)", idx);
                        }
                    }
                }
            }
            let total_pending: usize = events.iter().map(|x| if x.is_some() { 1 } else {0}).sum();
            assert_eq!(total_scheduled, events.len());
            assert!(total_dispatched <= total_scheduled);
            assert!(total_canceled <= total_scheduled);
            assert!(total_pending <= total_scheduled);
            // Cancellations can cause double-counting, when cancelling an already dispatched event.
            // So, best we can do is bracket the values.
            let definitely_alive = total_pending+total_dispatched;
            assert!(definitely_alive <= total_scheduled);
            assert!(definitely_alive+total_canceled >= total_scheduled);
        }
    }
}
