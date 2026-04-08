use alloc::string::String;
use core::{fmt, str::FromStr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use ts_capabilityversion::CapabilityVersion;
use ts_hexdump::{AsHexExt, Case};
use ts_http_util::{BytesBody, ClientExt, EmptyBody, HeaderName, HeaderValue, Http2, ResponseExt};
use ts_keys::{ChallengePublicKey, MachineKeyPair, MachinePublicKey};
use ts_packet::PacketMut;
use url::Url;
use zerocopy::network_endian::U32;

use crate::tokio::{MapStreamError, RegistrationError};

const CHALLENGE_MAGIC: [u8; 5] = [0xFF, 0xFF, 0xFF, b'T', b'S'];
const HANDSHAKE_HEADER_KEY: &str = "X-Tailscale-Handshake";
const MAX_CHALLENGE_LENGTH: usize = 1024;
const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";

lazy_static::lazy_static! {
    /// The version of the control protocol this node will use to communicate with the control
    /// plane; corresponds to the node's capability version.
    pub static ref CONTROL_PROTOCOL_VERSION: String = format!("Tailscale Control Protocol v{}", CapabilityVersion::CURRENT);
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    BadUrl(#[from] url::ParseError),
    #[error("could not read {field:?} from {stage} message: {err}")]
    Io {
        field: Option<&'static str>,
        stage: &'static str,
        err: std::io::Error,
    },
    #[error("could not connect to control server")]
    ConnectionFailed,
    #[error(transparent)]
    DeserializeFailed(#[from] serde_json::Error),
    #[error("invalid challenge length ({0} bytes); must be less than {MAX_CHALLENGE_LENGTH} bytes")]
    InvalidChallengeLength(usize),
    #[error("invalid magic value {0:X?} (expected {CHALLENGE_MAGIC:X?})")]
    InvalidChallengeMagic([u8; 5]),
    #[error("failed to start map stream: {0}")]
    MapStreamStartFailed(MapStreamError),
    #[error(transparent)]
    Noise(#[from] ts_control_noise::Error),
    #[error(transparent)]
    RegistrationFailed(#[from] RegistrationError),
    #[error("could not upgrade control connection to TS2021 protocol")]
    UpgradeFailed,

    #[error(transparent)]
    Http(#[from] ts_http_util::Error),
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlPublicKeys {
    legacy_public_key: MachinePublicKey,
    public_key: MachinePublicKey,
}

impl fmt::Display for ControlPublicKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key)
    }
}

#[tracing::instrument(skip_all, fields(%control_url), err)]
pub async fn connect(
    control_url: &Url,
    machine_keys: &MachineKeyPair,
) -> Result<Http2<BytesBody>, ConnectionError> {
    let h1_client = ts_http_util::http1::connect_tls(control_url).await?;

    let control_public_key = fetch_control_key(control_url).await?;

    let (handshake, init_msg) = ts_control_noise::Handshake::initialize(
        &CONTROL_PROTOCOL_VERSION,
        &machine_keys.private,
        &control_public_key,
        CapabilityVersion::CURRENT,
    );

    let mut conn = upgrade_ts2021(control_url, &init_msg, handshake, h1_client).await?;
    let _challenge_packet = read_challenge_packet(&mut conn).await?;

    let h2_conn = ts_http_util::http2::connect(conn).await?;
    Ok(h2_conn)
}

#[tracing::instrument(skip_all, fields(%control_url), ret, err, level = "trace")]
pub async fn fetch_control_key(control_url: &Url) -> Result<MachinePublicKey, ConnectionError> {
    let mut key_url = control_url.join("/key")?;
    key_url.set_scheme("https").unwrap();

    key_url
        .query_pairs_mut()
        .extend_pairs([("v", CapabilityVersion::CURRENT.to_string())]);

    let client = ts_http_util::http1::connect_tls::<EmptyBody>(&key_url).await?;
    let response = client.get(&key_url, None).await?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::error!(
            status_code = status.as_str(),
            "failed to retrieve control server machine public key"
        );

        return Err(ConnectionError::ConnectionFailed);
    }

    let control_keys: ControlPublicKeys = serde_json::from_slice(&response.collect_bytes().await?)?;
    let control_public_key = control_keys.public_key;

    Ok(control_public_key)
}

#[tracing::instrument(skip_all, fields(%control_url, %init_msg), err)]
pub async fn upgrade_ts2021(
    control_url: &Url,
    init_msg: &str,
    mut handshake: ts_control_noise::Handshake,
    h1_client: impl ts_http_util::Client<EmptyBody>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + 'static, ConnectionError> {
    let ts2021_url = control_url.join("/ts2021")?;

    tracing::trace!(
        %ts2021_url,
        "started NoiseIK handshake, upgrading to TS2021"
    );

    let resp = h1_client
        .send(ts_http_util::make_upgrade_req(
            &ts2021_url,
            UPGRADE_HEADER_VALUE,
            [(
                HeaderName::from_str(HANDSHAKE_HEADER_KEY).unwrap(),
                HeaderValue::from_str(init_msg).expect("handshake header is valid"),
            )],
        )?)
        .await?;

    let upgraded = ts_http_util::do_upgrade(resp)
        .await
        .map_err(|_e| ConnectionError::UpgradeFailed)?;

    let conn = handshake.complete(upgraded).await?;

    tracing::debug!("upgraded control connection from HTTP/1.1 to TS2021");

    Ok(conn)
}

#[tracing::instrument(skip_all, ret, err, level = "trace")]
pub async fn read_challenge_packet(
    conn: &mut (impl AsyncRead + Unpin),
) -> Result<ChallengePublicKey, ConnectionError> {
    let mut magic = [0u8; CHALLENGE_MAGIC.len()];

    conn.read_exact(&mut magic)
        .await
        .map_err(|err| ConnectionError::Io {
            field: Some("magic"),
            stage: "challenge",
            err,
        })?;
    if magic != CHALLENGE_MAGIC {
        return Err(ConnectionError::InvalidChallengeMagic(magic));
    }

    let mut challenge_len: U32 = 0.into();
    conn.read_exact(challenge_len.as_mut())
        .await
        .map_err(|err| ConnectionError::Io {
            field: Some("length"),
            stage: "challenge",
            err,
        })?;
    let challenge_len = challenge_len.get() as usize;
    if challenge_len > MAX_CHALLENGE_LENGTH {
        return Err(ConnectionError::InvalidChallengeLength(challenge_len));
    }

    let mut json = PacketMut::new(challenge_len);
    conn.read_exact(json.as_mut())
        .await
        .map_err(|err| ConnectionError::Io {
            field: Some("body"),
            stage: "challenge",
            err,
        })?;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ChallengePacket {
        node_key_challenge: ChallengePublicKey,
    }

    tracing::trace!(
        "challenge packet:\n{}",
        json.iter()
            .hexdump(Case::Lower)
            .flatten()
            .collect::<String>()
    );

    let packet = serde_json::from_slice::<ChallengePacket>(&json[..])?;
    Ok(packet.node_key_challenge)
}
