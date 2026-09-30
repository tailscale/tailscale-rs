use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls,
    rustls::{
        ClientConfig,
        client::danger::ServerCertVerified,
        pki_types::{CertificateDer, UnixTime},
    },
};

use crate::ServerName;

/// Establishes a TLS stream with a server over an existing connection, skipping certificate
/// verification entirely. Only for use in tests with self-signed certificates.
pub async fn connect_insecure<Io>(
    server_name: ServerName<'_>,
    io: Io,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    tracing::warn!(server_name = %server_name.to_str(), "connecting insecure TLS");

    let rustls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(rustls_config));
    let stream = connector.connect(server_name.to_owned(), io).await?;

    Ok(stream)
}

/// A TLS certificate verifier that accepts any certificate. Only for use in tests.
#[derive(Debug)]
struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
