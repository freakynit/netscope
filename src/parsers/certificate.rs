//! Small X.509 metadata extractor used after a proxy TLS handshake.
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_after: String,
}

pub fn parse_certificate(der: &[u8]) -> Result<CertificateSummary, String> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|error| format!("invalid X.509 certificate: {error}"))?;
    if !remaining.is_empty() {
        return Err("trailing data after X.509 certificate".into());
    }
    let tbs = &certificate.tbs_certificate;
    Ok(CertificateSummary {
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        serial: tbs.raw_serial_as_string(),
        not_after: tbs.validity().not_after.to_string(),
    })
}
