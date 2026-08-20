/// TLS client configuration for the node.
///
/// Two modes:
///   --accept-any-cert    : skips all verification (HTB lab convenience)
///   --fingerprint <hex>  : pins to the exact cert the proxy printed at startup
///
/// In production you'd bake the fingerprint into the binary at compile time
/// using an env! macro or build script — no flags needed.

use anyhow::Result;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, ClientConfig, Error as TlsError, ServerName,
};
use std::{sync::Arc, time::SystemTime};

pub fn build_client_config(accept_any: bool, fingerprint: Option<&str>) -> Result<ClientConfig> {
    if accept_any {
        return Ok(make_dangerous_config());
    }

    if let Some(fp) = fingerprint {
        let expected = fp.to_lowercase();
        return Ok(make_pinned_config(expected));
    }

    // Default: use system roots (webpki-roots would go here; for now dangerous)
    // For HTB labs accept_any is the practical choice — warn loudly
    tracing::warn!(
        "No --fingerprint or --accept-any-cert specified. \
         Defaulting to accept-any (use --fingerprint for production)"
    );
    Ok(make_dangerous_config())
}

// ── Accept-any verifier ───────────────────────────────────────────────────────

fn make_dangerous_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    config.enable_sni = false;
    config
}

struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

// ── Fingerprint-pinned verifier ───────────────────────────────────────────────

fn make_pinned_config(fingerprint: String) -> ClientConfig {
    ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { fingerprint }))
        .with_no_client_auth()
}

struct PinnedVerifier {
    fingerprint: String,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // SHA-256 fingerprint of the DER-encoded cert
        let fp = sha256_hex(&end_entity.0);
        if fp == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::error!(
                "Cert fingerprint mismatch!\n  got:      {}\n  expected: {}",
                fp, self.fingerprint
            );
            Err(TlsError::General("Certificate fingerprint mismatch".into()))
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    // NOTE: the proxy's certs.rs uses a non-crypto hash as placeholder —
    // keep this consistent. When you swap to sha2 crate on the proxy side,
    // update this to match.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}
