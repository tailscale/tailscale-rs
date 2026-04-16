use alloc::string::String;
use core::{fmt, str::FromStr};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use ts_capabilityversion::CapabilityVersion;
use ts_http_util::{BytesBody, ClientExt, EmptyBody, HeaderName, HeaderValue, Http2, ResponseExt};
use ts_keys::{MachineKeyPair, MachinePublicKey};
use url::Url;
use zerocopy::network_endian::U32;

use crate::tokio::{MapStreamError, RegistrationError, prefixed_reader::PrefixedReader};

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

    let conn = upgrade_ts2021(control_url, &init_msg, handshake, h1_client).await?;

    // The early payload (challenge packet) is optional. The server may send
    // the magic prefix [FF FF FF 'T' 'S'] followed by a JSON challenge, or it
    // may go straight to HTTP/2 (whose first frame starts with different bytes).
    // Read the first 9 bytes (same size as an HTTP/2 frame header) and check.
    let conn = read_challenge_packet(conn).await?;

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

/// Read the optional early payload (challenge packet) from the server.
///
/// The server may send a challenge packet with magic prefix [FF FF FF 'T' 'S'] followed
/// by a JSON payload, or it may go straight to HTTP/2. This function checks for the magic header
/// and consumes the payload if present, otherwise chaining the bytes back for consumption by the
/// HTTP/2 parser.
#[tracing::instrument(skip_all, err, level = "trace")]
pub async fn read_challenge_packet<Conn>(
    mut conn: Conn,
) -> Result<PrefixedReader<Conn>, ConnectionError>
where
    Conn: AsyncRead + Unpin,
{
    let mut magic = [0u8; CHALLENGE_MAGIC.len()];

    conn.read_exact(&mut magic)
        .await
        .map_err(|err| ConnectionError::Io {
            field: Some("header"),
            stage: "early_payload",
            err,
        })?;

    // This isn't an early challenge payload, it's the start of the HTTP/2 header -- chain it back
    if magic != CHALLENGE_MAGIC {
        return Ok(PrefixedReader::new(conn, Bytes::copy_from_slice(&magic)));
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

    // Read and discard the challenge JSON.
    let mut limited = conn.take(challenge_len as _);
    tokio::io::copy(&mut limited, &mut tokio::io::sink())
        .await
        .map_err(|err| ConnectionError::Io {
            field: Some("body"),
            stage: "challenge",
            err,
        })?;

    tracing::trace!(
        n_bytes = challenge_len,
        "read and discarded early challenge payload"
    );

    Ok(PrefixedReader::new(
        limited.into_inner(),
        Default::default(),
    ))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// Build a challenge packet: magic + big-endian length + JSON body.
    fn make_challenge(json: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CHALLENGE_MAGIC);
        buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
        buf.extend_from_slice(json);
        buf
    }

    /// Test that when the server sends an early challenge packet (production control
    /// server behavior), the magic+length+JSON is consumed and subsequent HTTP/2 data
    /// is passed through unmodified.
    #[tokio::test]
    async fn challenge_present() {
        let json = b"{\"nodeKeyChallenge\":\"test\"}";
        let payload = b"HTTP/2 data after challenge";

        let mut data = make_challenge(json);
        data.extend_from_slice(payload);

        let (mut writer, reader) = duplex(1024);
        writer.write_all(&data).await.unwrap();
        drop(writer);

        let mut conn = read_challenge_packet(reader).await.unwrap();

        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);
    }

    /// Test that when the server skips the early challenge and goes straight to HTTP/2
    /// (testcontrol behavior), all bytes are preserved -- the 9-byte peek that didn't
    /// match the magic is chained back so the HTTP/2 parser sees the full stream.
    #[tokio::test]
    async fn challenge_absent() {
        let payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        let (mut writer, reader) = duplex(1024);
        writer.write_all(payload).await.unwrap();
        drop(writer);

        let mut conn = read_challenge_packet(reader).await.unwrap();

        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);
    }
}
