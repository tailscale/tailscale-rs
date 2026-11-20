#![cfg(feature = "metrics")]

use crate::env::Env;
use kameo::actor::ActorRef;
use kameo::message::{Context, Message};
use std::ops::Sub;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;
use ts_control::StateUpdate;
use ts_logtail::client::LogtailClient;
use ts_logtail::id::LogtailPrivateId;
use ts_logtail::model::{LogEntryBuilder, MetricsExportType};
use ts_metrics_core::{Metrics, MetricsSnapshot};

const NAME_REPORT_INTERVAL: Duration = Duration::from_hours(1);

pub struct LogtailExporter {
    last_name_report: Instant,
    metrics: Arc<Metrics>,
    prev_snapshot: MetricsSnapshot,
    logtail_client: LogtailClient,
    log_entry_builder: LogEntryBuilder
}

#[derive(Clone)]
pub struct Args {
    pub env: Env,
    pub crate_features: String,
    pub logtail_id: LogtailPrivateId,
}

impl kameo::Actor for LogtailExporter {
    type Args = Args;
    type Error = crate::error::Error;

    async fn on_start(args: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        args.env.scheduler
            .tell(
                kameo_actors::scheduler::SetInterval::new(
                    slf.downgrade(),
                    Duration::from_secs(15),
                    Tick,
                )
                .set_missed_tick_behaviour(MissedTickBehavior::Skip),
            )
            .await?;

        let collection = "tailnode.log.tailscale.io";

        Ok(LogtailExporter {
            last_name_report: Instant::now().sub(NAME_REPORT_INTERVAL),
            metrics: args.env.metrics.clone(),
            prev_snapshot: MetricsSnapshot::new(&*args.env.metrics),
            logtail_client: LogtailClient::new(collection, args.logtail_id),
            log_entry_builder: LogEntryBuilder::new(&args.crate_features),
        })
    }
}

#[derive(Copy, Clone)]
struct Tick;

impl Message<Tick> for LogtailExporter {
    type Reply = ();

    async fn handle(&mut self, _: Tick, _: &mut Context<Self, Self::Reply>) {
        let cur_snapshot = MetricsSnapshot::new(&*self.metrics);
        let export_type = if Instant::now().sub(self.last_name_report).ge(&NAME_REPORT_INTERVAL) {
            MetricsExportType::FULL
        } else {
            MetricsExportType::DELTA
        };

        let Some(le) = self.log_entry_builder.new_metrics_export(export_type, &self.prev_snapshot, &cur_snapshot) else {
            return;
        };
        if self.logtail_client.post_log_entry(&le).await.is_err() {
            return;
        }
        
        self.prev_snapshot = cur_snapshot;
        if export_type == MetricsExportType::FULL {
            self.last_name_report = Instant::now();
        }
    }
}

impl Message<Arc<StateUpdate>> for LogtailExporter {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<StateUpdate>, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(log_auth_tokens) = &msg.log_auth_tokens else {
            return;
        };
        let Some(log_auth_token) = log_auth_tokens.iter().last() else {
            return;
        };
        self.logtail_client.update_auth_token(log_auth_token);
    }
}