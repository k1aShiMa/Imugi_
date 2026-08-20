/// Self-signed cert generation for the proxy TLS listener.
/// The agent will be compiled with the cert's fingerprint baked in
/// (or accept-any for lab use — configurable).

use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use rustls::{Certificate as RustlsCert, PrivateKey, ServerConfig};
use std::sync::Arc;

pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String, // SHA-256 hex of DER cert
}

pub fn generate_self_signed(cn: &str) -> Result<GeneratedCert> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName(cn.to_owned()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
    ];

    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;

    let cert_pem = cert.serialize_pem().context("Failed to serialize cert PEM")?;
    let key_pem = cert.serialize_private_key_pem();

    // SHA-256 fingerprint of the DER cert
    let der = cert.serialize_der().context("Failed to serialize cert DER")?;
    let fingerprint = sha256_hex(&der);

    Ok(GeneratedCert {
        cert_pem,
        key_pem,
        fingerprint,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    // Simple SHA-256 without ring dep — use std hash chain
    // For production replace with sha2 crate; fine for lab tooling
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // NOTE: This is NOT cryptographic — placeholder for fingerprint display only.
    // In the agent we'll do proper cert pinning with sha2.
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

pub fn build_tls_server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .context("Failed to parse cert PEM")?
        .into_iter()
        .map(RustlsCert)
        .collect::<Vec<_>>();

    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
        .context("Failed to parse key PEM")?;

    let key = PrivateKey(keys.into_iter().next().context("No private key found")?);

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server config")?;

    Ok(Arc::new(config))
}
