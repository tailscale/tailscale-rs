//! Stream packet filter updates from control.

use std::sync::Arc;

use clap::Parser as _;
use futures::StreamExt;
use tokio::sync::Mutex;
use ts_packetfilter as pf;
use ts_packetfilter_state as pf_state;

/// Stream packet filters from control.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    #[clap(flatten)]
    common: ts_cli_util::CommonArgs,
}

#[tokio::main]
async fn main() -> ts_cli_util::Result<()> {
    ts_cli_util::init_tracing();

    let args = Args::parse();

    let (_, _, _, stream) = args.common.connect_control().await?;
    let state = Arc::new(Mutex::new(pf::BTreeFilter::new()));

    tracing::info!("streaming packet filter updates");

    stream
        .filter_map(async |x| x.packetfilter.clone())
        .for_each(
            async |filter| {
                tracing::info!(new_rule_base = ?filter.0, new_rule_map = ?filter.1, "filter update received");

                let mut state = state.lock().await;

                pf_state::apply_update(&mut *state, filter.0.clone(), &filter.1);
                tracing::info!(?state, "filter update applied");
            }
       )
        .await;

    Ok(())
}
