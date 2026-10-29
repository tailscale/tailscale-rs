use std::sync::{Arc, Mutex};

use napi::{Env, bindgen_prelude::*};
use napi_derive::napi;
use tokio_util::sync::CancellationToken;

use crate::error::{Code, js_err};

/// Cancels an operation; the TypeScript wrapper creates one per `AbortSignal`.
#[napi]
#[derive(Default)]
pub struct CancelToken(CancellationToken);

#[napi]
impl CancelToken {
    /// Create a new, uncancelled token.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel the operation(s) this token was passed to.
    #[napi]
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

/// A resource which can be closed explicitly from JS, rather than only when its JS object is
/// garbage collected.
///
/// Closing drops this handle's reference to the resource and cancels any operations in flight.
/// Those operations hold their own references, so the resource itself is dropped once they have
/// finished being cancelled.
pub(crate) struct Closable<T> {
    inner: Mutex<Option<Arc<T>>>,
    closed: CancellationToken,
}

impl<T: Send + Sync + 'static> Closable<T> {
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(Some(Arc::new(value))),
            closed: CancellationToken::new(),
        }
    }

    /// Get the resource, or an error if it has been closed.
    pub fn get(&self) -> Result<Arc<T>> {
        self.inner
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| js_err(Code::SocketClosed, "closed"))
    }

    /// Close the resource, cancelling any operations in flight.
    ///
    /// Returns this handle's reference to the resource, or `None` if it was already closed.
    pub fn close(&self) -> Option<Arc<T>> {
        let value = self.inner.lock().unwrap().take();
        self.closed.cancel();
        value
    }

    /// Run `op` on the resource in a future, returning a promise for its result.
    ///
    /// The promise is rejected if the resource is closed, or `cancel` is cancelled, before `op`
    /// completes. If `op`'s result is already available when that happens, it resolves with the
    /// result instead, so that, e.g., an accepted connection or received data isn't discarded.
    pub fn spawn<'env, R, F>(
        &self,
        env: &'env Env,
        cancel: Option<&CancelToken>,
        op: impl FnOnce(Arc<T>) -> F + Send + 'static,
    ) -> Result<PromiseRaw<'env, R>>
    where
        R: ToNapiValue + Send + 'static,
        F: Future<Output = Result<R>> + Send + 'static,
    {
        let value = self.get();
        let closed = self.closed.clone();
        let cancel = cancel.map(|c| c.0.clone()).unwrap_or_default();

        env.spawn_future(async move {
            let value = value?;
            // `op` is polled first, so that once it has its result, it's returned even if the
            // resource is closed or the operation cancelled at the same time.
            tokio::select! {
                biased;
                result = op(value) => result,
                _ = closed.cancelled() => Err(js_err(Code::SocketClosed, "closed")),
                _ = cancel.cancelled() => Err(js_err(Code::Aborted, "operation aborted")),
            }
        })
    }
}

/// Run `fut` in a promise, which is rejected if `cancel` is cancelled before `fut` completes.
///
/// As for [`Closable::spawn`], if `fut`'s result is already available when `cancel` is
/// cancelled, the promise resolves with it.
pub(crate) fn spawn_cancellable<'env, R, F>(
    env: &'env Env,
    cancel: Option<&CancelToken>,
    fut: F,
) -> Result<PromiseRaw<'env, R>>
where
    R: ToNapiValue + Send + 'static,
    F: Future<Output = Result<R>> + Send + 'static,
{
    let cancel = cancel.map(|c| c.0.clone()).unwrap_or_default();

    env.spawn_future(async move {
        tokio::select! {
            biased;
            result = fut => result,
            _ = cancel.cancelled() => Err(js_err(Code::Aborted, "operation aborted")),
        }
    })
}
