use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, RegisterAuth, RegisterRequest, RegisterResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use url::Url;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("peer config missing auth key; needed for registration")]
    AuthKeyMissing,
    #[error("failed to deserialize registration response body: {0}")]
    DeserializeFailed(serde_json::Error),
    #[error(transparent)]
    HttpError(#[from] ts_http_util::Error),
    #[error("machine was not authorized by control to join tailnet")]
    MachineNotAuthorized,
    #[error("failed to register node; control returned HTTP {0}")]
    RegistrationFailed(u16),
    #[error("failed to construct request")]
    Request,
    #[error("failed to serialize registration request body: {0}")]
    SerializeFailed(serde_json::Error),
    #[error(transparent)]
    Utf8Error(#[from] core::str::Utf8Error),
}

/// Result of authorizing with the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Authorization succeeded.
    Ok,
    /// Auth failed, user should navigate to the contained URL.
    AuthRequired(Url),
}

#[tracing::instrument(skip_all, fields(%register_url))]
pub async fn register(
    config: &crate::Config,
    register_url: &Url,
    auth_key: Option<&str>,
    node_keystate: &ts_keys::NodeState,
    http2_conn: &Http2<BytesBody>,
) -> Result<AuthResult, RegistrationError> {
    let node_public_key = node_keystate.node_keys.public;
    let network_lock_public_key = node_keystate.network_lock_keys.public;

    let register_req = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref(),
            app: &config.format_client_name(),
            ipn_version: crate::PKG_VERSION,
            ..Default::default()
        },
        nl_key: Some(network_lock_public_key),
        auth: auth_key.map(RegisterAuth::from),
        ephemeral: true,
        ..Default::default()
    };

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&register_req).map_err(RegistrationError::SerializeFailed)
    } else {
        serde_json::to_string(&register_req).map_err(RegistrationError::SerializeFailed)
    }?;

    tracing::trace!(
        url = %register_url.as_str(),
        %body,
        "sending registration request"
    );

    let response = http2_conn
        .post(
            register_url,
            [(
                LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
                node_public_key.to_string().parse().unwrap(),
            )],
            Bytes::from(body).into(),
        )
        .await?;

    let status = response.status();

    tracing::debug!(%status, "received registration response");

    if !status.is_success() {
        // Attempt to collect the body to log the error, truncating to prevent spamming the logs.
        let mut body = response.collect_bytes().await.unwrap_or_default();
        body.truncate(512);
        let body = core::str::from_utf8(&body).unwrap_or("<invalid utf8>");
        tracing::error!(%body, %status, "registration failed");

        return Err(RegistrationError::RegistrationFailed(status.as_u16()));
    }

    let body = response.collect_bytes().await?;
    let body = core::str::from_utf8(&body)?;

    tracing::trace!(registration_response_body = %body);

    let register_resp: RegisterResponse =
        serde_json::from_str(body).map_err(RegistrationError::DeserializeFailed)?;

    if !register_resp.machine_authorized {
        if !register_resp.auth_url.is_empty() {
            Ok(AuthResult::AuthRequired(
                register_resp
                    .auth_url
                    .parse()
                    .map_err(|_e| RegistrationError::MachineNotAuthorized)?,
            ))
        } else {
            Err(RegistrationError::MachineNotAuthorized)
        }
    } else {
        Ok(AuthResult::Ok)
    }
}
