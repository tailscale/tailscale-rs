use core::time::Duration;

use crate::runtime::Executor;

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
