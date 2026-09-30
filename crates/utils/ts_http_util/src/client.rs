use std::sync::Arc;

use http::{HeaderName, HeaderValue, Request, Response};
use hyper::body::{Body, Incoming};

use crate::Error;

/// An HTTP client that can asynchronously send requests and receive responses.
///
/// This trait is HTTP version agnostic; it can be implemented for any version of HTTP.
/// Version-specific features, such as connecting to a server or the HTTP/1.1 protocol upgrade
/// mechanism, must be implemented individually for concrete implementations in addition to the
/// `send` method.
pub trait Client<B>
where
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    /// Sends the given HTTP [`Request`] to the connected server and returns the [`Response`].
    ///
    /// Note that the [`Response`] body of [`Incoming`] means the body must be collected separately
    /// from the [`Response`] status and headers; this allows the status/headers to be checked
    /// before the full body has arrived.
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send;
}

/// Extension trait adding specific HTTP method functions (GET, POST, etc.) on top of the base
/// [`Client`] trait.
pub trait ClientExt<B>: Client<B>
where
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    /// Sends an HTTP GET request to the connected server and returns the [`Response`].
    ///
    /// By definition, HTTP GET requests do not contain a body. Note that the [`Response`] body of
    /// [`Incoming`] means the body must be collected separately from the [`Response`] status and
    /// headers; this allows the status/headers to be checked before the full body has arrived.
    fn get(
        &self,
        url: &url::Url,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>>
    where
        B: Default,
    {
        let mut req = Request::get(url.as_str());

        if let Some(hdrs) = req.headers_mut() {
            hdrs.extend(crate::host_header(url));
            hdrs.extend(headers);
        }

        async move {
            let req = req.body(Default::default()).map_err(|e| {
                tracing::error!(error = %e, "constructing request");
                Error::InvalidInput
            })?;

            self.send(req).await
        }
    }

    /// Sends an HTTP POST request to the connected server and returns the [`Response`].
    ///
    /// Note that the [`Response`] body of [`Incoming`] means the body must be collected separately
    /// from the [`Response`] status and headers; this allows the status/headers to be checked
    /// before the full body has arrived.
    fn post(
        &self,
        url: &url::Url,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
        body: B,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> {
        let mut req = Request::post(url.as_str());

        if let Some(hdrs) = req.headers_mut() {
            hdrs.extend(crate::host_header(url));
            hdrs.extend(headers);
        }

        async move {
            let req = req.body(body).map_err(|e| {
                tracing::error!(error = %e, "constructing request");
                Error::InvalidInput
            })?;

            self.send(req).await
        }
    }
}

impl<T, B> ClientExt<B> for T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
}

impl<T, B> Client<B> for Arc<T>
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        self.as_ref().send(req)
    }
}

impl<T, B> Client<B> for &T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        (**self).send(req)
    }
}

impl<T, B> Client<B> for &mut T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        (**self).send(req)
    }
}
