use core::time::Duration;

use netcore::smoltcp;
use tracing::Instrument;

/// Run the netstack in the current thread.
///
/// Expect this function to block forever.
#[tracing::instrument(skip_all, fields(?poll_max_delay))]
pub fn run_blocking(
    netstack: &mut netcore::Netstack,
    dev: &mut impl smoltcp::phy::Device,
    mut now: impl FnMut() -> smoltcp::time::Instant,
    poll_max_delay: Duration,
) {
    loop {
        let now = now();
        let span = tracing::trace_span!("loop", %now, delay = tracing::field::Empty).entered();

        netstack.poll_device_io(now, &mut *dev);

        let delay = netstack
            .poll_delay(now)
            .unwrap_or(Duration::MAX)
            .min(poll_max_delay);

        span.record("delay", tracing::field::debug(delay));

        tracing::trace!("wait");

        match netstack.wait_for_cmd_blocking(Some(delay)) {
            Ok(cmd) => {
                netstack.process_one_cmd(cmd);
                // process any more commands pending in the channel before polling device i/o
                netstack.process_cmds();
            }
            Err(netcore::flume::RecvTimeoutError::Timeout) => {
                // no commands received, fall through to poll for i/o
            }
            Err(netcore::flume::RecvTimeoutError::Disconnected) => {
                // this can't occur: netstack holds a sender, so the channel can't close until it
                // drops
                unreachable!("internal command channel closed")
            }
        }
    }
}

/// Run the netstack indefinitely.
#[tracing::instrument(skip_all)]
pub async fn run(
    netstack: &mut netcore::Netstack,
    dev: &mut (impl netcore::AsyncWakeDevice + smoltcp::phy::Device + Unpin),
    mut now: impl FnMut() -> smoltcp::time::Instant,
    sleep: impl AsyncFn(Duration) + Clone,
) {
    use futures_util::FutureExt;

    loop {
        let now = now();

        let delay = netstack.poll_delay(now);
        let span = tracing::trace_span!("loop", %now, ?delay);
        let cmd_fut = netstack.wait_for_cmd();

        tracing::trace!(parent: &span, "select");

        futures_util::select_biased![
            _ = netstack.wait_io_async(now, dev)
                .instrument(span.clone())
                .fuse() =>
            {
                tracing::trace!(parent: &span, "device wakeup");
            },
            _ = option_timeout(sleep.clone(), delay).instrument(span.clone()).fuse() => {
                tracing::trace!(parent: &span, "timeout wakeup");
            },
            cmd = cmd_fut.instrument(span.clone()).fuse() => {
                span.in_scope(|| {
                    tracing::trace!("command wakeup");

                    if let Some(cmd) = cmd {
                        netstack.process_one_cmd(cmd);
                    } else {
                        // this can't occur: netstack holds a sender for its own channel, so the receive
                        // channel can't close until the netstack itself drops
                        unreachable!("internal command channel closed");
                    }

                    // Process any more commands pending in the channel before polling device i/o
                    netstack.process_cmds();
                });
            }
        ]
    }
}

async fn option_timeout(sleep: impl AsyncFn(Duration), dur: Option<Duration>) {
    match dur {
        Some(dur) => sleep(dur).await,
        _ => core::future::pending().await,
    }
}
