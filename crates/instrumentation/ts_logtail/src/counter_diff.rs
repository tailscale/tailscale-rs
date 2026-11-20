use ts_metrics_core::MetricsSnapshot;

/// Iterator over the diffs between two `MetricsSnapshot`. On most exports, logtail only reports
/// counters that have changed since the last export.
pub struct CounterDiffIterator<'a, 'b> {
    idx: usize,
    prev: &'a MetricsSnapshot,
    cur: &'b MetricsSnapshot,
}

impl<'a, 'b> CounterDiffIterator<'a, 'b> {
    pub fn new(prev: &'a MetricsSnapshot, cur: &'b MetricsSnapshot) -> Self {
        CounterDiffIterator {
            idx: 0,
            prev,
            cur
        }
    }
}

impl <'a, 'b> Iterator for CounterDiffIterator<'a, 'b> {
    type Item = CounterDiff;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.prev.values.len() && self.prev.values[self.idx] == self.cur.values[self.idx] {
            self.idx += 1;
        }

        if self.idx == self.prev.values.len() {
            None
        } else {
            let diff = self.cur.values[self.idx] - self.prev.values[self.idx];
            self.idx += 1;
            Some(CounterDiff {
                metric_id: self.idx - 1,
                diff,
            })
        }
    }
}

pub struct CounterDiff {
    pub metric_id: usize,
    pub diff: usize,
}