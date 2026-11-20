use crate::error::{Error, InternalErrorKind};
use crate::id::LogtailPrivateId;
use crate::model::LogEntry;
use reqwest::header::{AUTHORIZATION, HeaderMap};
use reqwest_tracing::TracingMiddleware;

pub struct LogtailClient {
    client: reqwest_middleware::ClientWithMiddleware,
    logtail_url: String,
    auth_token: String,
}

impl LogtailClient {
    pub fn new(collection: &str, logtail_privateid: LogtailPrivateId) -> Self {
        let privateid_str = hex::encode(logtail_privateid.0);
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(TracingMiddleware::default())
            .build();
        LogtailClient {
            client,
            logtail_url: format!("https://log.tailscale.com/c/{}/{}", collection, privateid_str),
            auth_token: String::new(),
        }
    }

    pub fn update_auth_token(&mut self, new_token: &String) {
        self.auth_token = new_token.to_owned();
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn post_log_entry(&self, log_entry: &LogEntry<'_, '_, '_>) -> Result<(), Error> {
        let mut req = self.client.post(&self.logtail_url)
            .body(serde_json::to_vec(log_entry)?);
        if self.auth_token != "" {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {}", self.auth_token).parse()?);
            req = req.headers(headers);
        }

        let resp = req.send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            tracing::error!(status = %resp.status(), "error sending log entry");
            Err(Error::Internal(InternalErrorKind::Http))
        }
    }
}