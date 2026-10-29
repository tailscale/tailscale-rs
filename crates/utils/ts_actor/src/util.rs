use core::time::Duration;

use crate::{Error, Handle, ProcContext, ToProcName, runtime::Executor};

// Adapted from tokio/src/task/error.rs
#[cfg(feature = "std")]
#[allow(unused)]
pub fn panic_payload_as_str(payload: &(dyn core::any::Any + Send)) -> &str {
    // Panic payloads are almost always `String` (if invoked with formatting arguments)
    // or `&'static str` (if invoked with a string literal).
    //
    // Non-string panic payloads have niche use-cases,
    // so we don't really need to worry about those.
    if let Some(s) = payload.downcast_ref::<alloc::string::String>() {
        return s;
    }

    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return s;
    }

    "<non-string panic payload>"
}

/// Wait for the specified duration if `Some`, otherwise pend forever.
pub async fn option_timeout(exc: &dyn Executor, dur: Option<Duration>) {
    if let Some(dur) = dur {
        let sleep_fut = exc.sleep(dur);
        sleep_fut.await
    } else {
        core::future::pending().await
    }
}

/// An RAII guard around a monitor handle.
///
/// Use this to express a temporary monitor in a function scope, e.g. It's not required to
/// hold this in process state, as all monitors related to a process are automatically
/// cleaned up when it dies.
pub struct MonitorGuard<'a>(Handle, &'a ProcContext);

impl<'a> MonitorGuard<'a> {
    /// Construct a new guard on the given process.
    pub async fn new(ctx: &'a ProcContext, proc: &dyn ToProcName) -> Result<Self, Error> {
        let handle = ctx.monitor(proc).await?;

        Ok(Self(handle, ctx))
    }

    /// Retrieve the monitor handle.
    pub const fn handle(&self) -> Handle {
        self.0
    }

    /// Forget this guard, preventing it from unmonitoring the target process on drop.
    pub fn forget(self) -> Handle {
        let handle = self.0;
        core::mem::forget(self);

        handle
    }
}

impl Drop for MonitorGuard<'_> {
    fn drop(&mut self) {
        // Not an error to drop this, it means the process doesn't exist anymore.
        let _result = self.1.unmonitor(self.0);
    }
}
