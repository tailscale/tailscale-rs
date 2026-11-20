use crate::counter_diff::CounterDiffIterator;
use crate::{enc, id};
use chrono::{DateTime, Utc};
use serde::Serializer;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};
use ts_metrics_core::{Metrics, MetricsSnapshot};

const PKG_VERSION: &str = if let Some(version) = option_env!("CARGO_PKG_VERSION") {
    version
} else {
    ""
};

static PROC_SEQ: AtomicUsize = AtomicUsize::new(1); // 0 is "not present"

pub struct LogEntryBuilder {
    version_str: String
}

impl LogEntryBuilder {
    pub fn new(features_str: &str) -> Self {
        LogEntryBuilder {
            version_str: format!("metrics for tailscale-rs {} features={}", PKG_VERSION, features_str)
        }
    }
}

impl <'a> LogEntryBuilder {
    pub fn new_message(&self, text: &'a str) -> LogEntry<'a, '_, '_> {
        LogEntry {
            logtail: Logtail::new(),
            text,
            metrics: None,
        }
    }
}

impl<'a, 'b, 'c> LogEntryBuilder {
    pub fn new_metrics_export(&'a self, export_type: MetricsExportType, prev: &'b MetricsSnapshot, cur: &'c MetricsSnapshot) -> Option<LogEntry<'a, 'b, 'c>> {
        Some(export_type)
            .filter(|et| match et {
                MetricsExportType::FULL => true,
                MetricsExportType::DELTA => CounterDiffIterator::new(prev, cur).next().is_some(),
            })
            .map(|_| LogEntry {
                logtail: Logtail::new(),
                text: &self.version_str,
                metrics: Some(LogtailMetricsSerializer {
                    export_type,
                    prev,
                    cur,
                }),
            })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MetricsExportType {
    DELTA,
    FULL
}

#[derive(serde::Serialize)]
pub struct LogEntry<'a, 'b, 'c> {
    logtail: Logtail,
    text: &'a str,
    metrics: Option<LogtailMetricsSerializer<'b, 'c>>,
}

#[derive(serde::Serialize)]
struct Logtail {
    client_time: DateTime<Utc>,
    proc_id: u32,
    proc_seq: usize,
}

impl Logtail {
    fn new() -> Self {
        Logtail {
            client_time: Utc::now(),
            proc_id: id::PROC_ID.0,
            proc_seq: PROC_SEQ.fetch_add(1, Ordering::Relaxed)
        }
    }
}

struct LogtailMetricsSerializer<'a, 'b> {
    export_type: MetricsExportType,
    prev: &'a MetricsSnapshot,
    cur: &'b MetricsSnapshot,
}

impl<'a, 'b> Display for LogtailMetricsSerializer<'a, 'b> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut id_buf = enc::VarintBuf::new();
        let mut value_buf = enc::VarintBuf::new();

        match self.export_type {
            MetricsExportType::DELTA => {
                for diff in CounterDiffIterator::new(self.prev, self.cur) {
                    id_buf.encode((diff.metric_id + 1) as u64);
                    value_buf.encode(diff.diff as u64);
                    f.write_fmt(format_args!("I{}{}", id_buf, value_buf))?;
                }
            },
            MetricsExportType::FULL => {
                let mut iter = Metrics::NAMES.iter().enumerate();
                let mut name_len_buf = enc::VarintBuf::new();

                while let Some((metric_id, metric_name)) = iter.next() {
                    name_len_buf.encode(metric_name.len() as u64);
                    id_buf.encode((metric_id + 1) as u64);
                    value_buf.encode(self.cur.values[metric_id] as u64);
                    f.write_fmt(format_args!("N{}{}S{}{}", name_len_buf, metric_name, id_buf, value_buf))?;
                }
            }
        }

        Ok(())
    }
}

impl<'a, 'b> serde::Serialize for LogtailMetricsSerializer<'a, 'b> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}