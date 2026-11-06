//! Administration of Ghostlink servers through their management API, using Outline-style
//! management keys: `{"apiUrl":"https://HOST:PORT/SECRET","certSha256":"HEX"}`.
//!
//! The server's self-signed certificate is pinned inside the TLS handshake, so the request,
//! whose path carries the secret, is never sent to a server that does not hold the pinned
//! certificate's private key.

use anyhow::{bail, Context, Result};
use ghostlink_contracts::ServerOp;
use reqwest::{redirect::Policy, Method};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const MAX_RESPONSE: usize = 1024 * 1024;
const PROTOCOLS: [&str; 4] = ["amneziawg", "wireguard", "vless", "shadowsocks"];

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementKey {
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "certSha256")]
    pub cert_sha256: String,
}

impl fmt::Debug for ManagementKey {
    // The URL carries the secret; never let it reach logs through Debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagementKey(..)")
    }
}

impl ManagementKey {
    /// Parses and normalizes a management key, refusing anything but a plain HTTPS URL with an
    /// explicit secret path and a SHA-256 certificate fingerprint.
    pub fn parse(text: &str) -> Result<Self> {
        let key: Self = serde_json::from_str(text.trim())
            .context(r#"A management key looks like {"apiUrl":"https://…","certSha256":"…"}"#)?;
        let url =
            url::Url::parse(&key.api_url).context("The management key's apiUrl is not a URL")?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            bail!("The management key must use a plain https:// URL");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("The management key's URL must not have a query or fragment");
        }
        let host = match url.host() {
            Some(url::Host::Domain(domain)) if !domain.is_empty() => domain.to_ascii_lowercase(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
            _ => bail!("The management key has no server address"),
        };
        let port = url.port_or_known_default().unwrap_or(443);
        let secret = url.path().trim_start_matches('/');
        if !(16..=128).contains(&secret.len())
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("The management key's secret path is missing or malformed");
        }
        let pin = key.cert_sha256.replace(':', "");
        if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("certSha256 must be a 64-digit hexadecimal SHA-256 fingerprint");
        }
        Ok(Self {
            api_url: format!("https://{host}:{port}/{secret}"),
            cert_sha256: pin.to_ascii_uppercase(),
        })
    }

    /// The server host (IPv6 in brackets) and port, without the secret.
    pub fn host_port(&self) -> (String, u16) {
        let endpoint = self.endpoint();
        match endpoint.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().unwrap_or(443)),
            None => (endpoint, 443),
        }
    }

    /// The server address without the secret, for display.
    pub fn endpoint(&self) -> String {
        let rest = self.api_url.trim_start_matches("https://");
        rest.split('/').next().unwrap_or_default().to_string()
    }

    fn pin(&self) -> [u8; 32] {
        let mut pin = [0u8; 32];
        // parse() guarantees 64 hex digits.
        let _ = hex::decode_to_slice(&self.cert_sha256, &mut pin);
        pin
    }
}

/// Why an administration call failed. Messages never include the management key.
#[derive(Debug)]
pub enum AdminError {
    /// The server could not be reached in time.
    Unreachable,
    /// The server did not present the pinned certificate (or could not prove it holds it).
    IdentityMismatch,
    /// The address answered but is not a Ghostlink server (`outline` when it is Outline).
    NotGhostlink { outline: bool },
    /// The server refused the request; `message` is the server's own explanation.
    Rejected { status: u16, message: String },
    /// The request was invalid before it was sent.
    Invalid(String),
    /// The response was malformed or too large.
    InvalidResponse,
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable => f.write_str("The server did not answer; check its address, port and firewall"),
            Self::IdentityMismatch => f.write_str("The server's certificate does not match the management key; refusing to send the key"),
            Self::NotGhostlink { outline: true } => f.write_str("This is an Outline server; Ghostlink manages Ghostlink servers only (its ss:// keys still work as VPN keys)"),
            Self::NotGhostlink { outline: false } => f.write_str("The address answered but is not a Ghostlink server"),
            Self::Rejected { message, .. } => f.write_str(message),
            Self::Invalid(message) => f.write_str(message),
            Self::InvalidResponse => f.write_str("The server sent an unexpected response"),
        }
    }
}

/// Accepts exactly one certificate and still verifies the handshake signature, so a peer that
/// merely copied the (public) certificate cannot pass.
#[derive(Debug)]
struct PinnedCertificate {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
    mismatch: AtomicBool,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if constant_time_eq(&digest, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.store(true, Ordering::SeqCst);
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn numeric_id(value: &str) -> Result<&str, AdminError> {
    if (1..=10).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit()) {
        Ok(value)
    } else {
        Err(AdminError::Invalid(format!(
            "{value:?} is not a user or key ID"
        )))
    }
}

fn body(value: &impl Serialize) -> Result<Option<Value>, AdminError> {
    serde_json::to_value(value)
        .map(Some)
        .map_err(|_| AdminError::Invalid("Could not encode the request".into()))
}

/// Maps a typed operation to its API request. Only these fixed paths can ever be requested.
pub fn request(op: &ServerOp) -> Result<(Method, String, Option<Value>), AdminError> {
    Ok(match op {
        ServerOp::Info => (Method::GET, "/server".into(), None),
        ServerOp::Update { patch } => (Method::PATCH, "/server".into(), body(patch)?),
        ServerOp::UsersList => (Method::GET, "/users".into(), None),
        ServerOp::UserCreate { change } => (Method::POST, "/users".into(), body(change)?),
        ServerOp::UserUpdate { user, change } => (
            Method::PATCH,
            format!("/users/{}", numeric_id(user)?),
            body(change)?,
        ),
        ServerOp::UserDelete { user } => (
            Method::DELETE,
            format!("/users/{}", numeric_id(user)?),
            None,
        ),
        ServerOp::KeysList { user } => (
            Method::GET,
            format!("/users/{}/keys", numeric_id(user)?),
            None,
        ),
        ServerOp::KeyCreate { user, protocol, .. } => {
            if !PROTOCOLS.contains(&protocol.as_str()) {
                return Err(AdminError::Invalid(format!(
                    "Protocol must be one of {}",
                    PROTOCOLS.join(", ")
                )));
            }
            (
                Method::POST,
                format!("/users/{}/keys", numeric_id(user)?),
                Some(json!({ "protocol": protocol })),
            )
        }
        ServerOp::KeyDelete { user, key } => (
            Method::DELETE,
            format!("/users/{}/keys/{}", numeric_id(user)?, numeric_id(key)?),
            None,
        ),
        ServerOp::RulesGet => (Method::GET, "/rules".into(), None),
        ServerOp::RulesSet { rules } => (Method::PUT, "/rules".into(), body(rules)?),
        ServerOp::Metrics => (Method::GET, "/metrics".into(), None),
    })
}

fn clean_message(text: &str) -> String {
    let message: String = text.chars().filter(|c| !c.is_control()).take(300).collect();
    if message.trim().is_empty() {
        "The server refused the request".into()
    } else {
        message
    }
}

/// Sends one request to the server named by `key`.
pub async fn send(
    key: &ManagementKey,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, AdminError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCertificate {
        pin: key.pin(),
        provider: provider.clone(),
        mismatch: AtomicBool::new(false),
    });
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AdminError::Invalid("TLS is unavailable".into()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(Policy::none())
        .no_proxy()
        .http1_only()
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| AdminError::Invalid("TLS is unavailable".into()))?;
    let mut request = client
        .request(method, format!("{}{}", key.api_url, path))
        .header("Accept", "application/json");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(_) if verifier.mismatch.load(Ordering::SeqCst) => {
            return Err(AdminError::IdentityMismatch)
        }
        Err(_) => return Err(AdminError::Unreachable),
    };
    let status = response.status();
    let mut data = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if data.len() + chunk.len() > MAX_RESPONSE {
                    return Err(AdminError::InvalidResponse);
                }
                data.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Err(AdminError::Unreachable),
        }
    }
    let value: Value = if data.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&data) {
            Ok(value) => value,
            Err(_) if !status.is_success() => Value::Null,
            Err(_) => return Err(AdminError::InvalidResponse),
        }
    };
    if !status.is_success() {
        let message = value
            .get("error")
            .and_then(Value::as_str)
            .map(clean_message)
            .unwrap_or_else(|| match status.as_u16() {
                404 => {
                    "Not found on the server (check the ID, or the management key is out of date)"
                        .into()
                }
                _ => format!("The server answered HTTP {}", status.as_u16()),
            });
        return Err(AdminError::Rejected {
            status: status.as_u16(),
            message,
        });
    }
    Ok(value)
}

/// Runs a typed operation.
pub async fn call(key: &ManagementKey, op: &ServerOp) -> Result<Value, AdminError> {
    let (method, path, body) = request(op)?;
    send(key, method, &path, body).await
}

/// Confirms the key reaches a Ghostlink server and returns its `/server` description.
pub async fn probe(key: &ManagementKey) -> Result<Value, AdminError> {
    let info = match send(key, Method::GET, "/server", None).await {
        Err(AdminError::Rejected { status: 404, .. }) => {
            return Err(AdminError::NotGhostlink { outline: false })
        }
        other => other?,
    };
    if info.get("protocols").is_some_and(Value::is_object) {
        Ok(info)
    } else {
        Err(AdminError::NotGhostlink {
            outline: info.get("serverId").is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::OnceLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A self-signed certificate made for this test run only.
    fn identity() -> &'static (Vec<u8>, Vec<u8>) {
        static IDENTITY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        IDENTITY.get_or_init(|| {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::CertificateParams::new(vec!["ghostlink-test".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            (cert.der().to_vec(), key.serialize_der())
        })
    }

    fn fingerprint() -> String {
        hex::encode_upper(Sha256::digest(&identity().0))
    }

    /// A TLS 1.3 server that answers one canned response and reports whether any application
    /// bytes (the HTTP request, which carries the secret) arrived.
    async fn server(reply: String) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let cert = CertificateDer::from(identity().0.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity().1.clone()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buffer = [0u8; 4096];
                if let Ok(n) = tls.read(&mut buffer).await {
                    seen.extend_from_slice(&buffer[..n]);
                }
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            }
            let _ = seen_tx.send(seen);
        });
        (port, seen_rx)
    }

    fn key(port: u16, pin: &str) -> ManagementKey {
        ManagementKey::parse(&format!(
            r#"{{"apiUrl":"https://127.0.0.1:{port}/abcdefghijklmnop0123","certSha256":"{pin}"}}"#
        ))
        .unwrap()
    }

    const GHOSTLINK: &str = r#"{"name":"test","protocols":{"vless":{}}}"#;

    fn http(status: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    #[tokio::test]
    async fn pinned_certificate_is_accepted() {
        let (port, seen) = server(http("200 OK", GHOSTLINK)).await;
        let info = probe(&key(port, &fingerprint())).await.unwrap();
        assert_eq!(info["name"], "test");
        let request = String::from_utf8(seen.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /abcdefghijklmnop0123/server HTTP/1.1"));
    }

    #[tokio::test]
    async fn wrong_pin_fails_before_any_request_bytes() {
        let (port, seen) = server(http("200 OK", GHOSTLINK)).await;
        let error = probe(&key(port, &"AB".repeat(32))).await.unwrap_err();
        assert!(matches!(error, AdminError::IdentityMismatch), "{error}");
        assert!(
            seen.await.unwrap().is_empty(),
            "the secret path reached an unpinned server"
        );
    }

    #[tokio::test]
    async fn outline_servers_are_recognized() {
        let (port, _) = server(http("200 OK", r#"{"serverId":"x","name":"o"}"#)).await;
        let error = probe(&key(port, &fingerprint())).await.unwrap_err();
        assert!(
            matches!(error, AdminError::NotGhostlink { outline: true }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn server_errors_are_reported_without_the_key() {
        let (port, _) = server(http("400 Bad Request", r#"{"error":"names must be 1-64"}"#)).await;
        let error = call(&key(port, &fingerprint()), &ServerOp::UsersList)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "names must be 1-64");
    }

    #[test]
    fn management_keys_are_validated_and_normalized() {
        let key = ManagementKey::parse(
            r#" {"apiUrl":"https://VPN.Example.com:8443/AbC_def-1234567890","certSha256":"ab:cd"} "#,
        );
        assert!(key.is_err(), "short fingerprint accepted");
        let pin = "ab".repeat(32);
        let key = ManagementKey::parse(&format!(
            r#"{{"apiUrl":"https://VPN.Example.com:8443/AbC_def-1234567890","certSha256":"{pin}"}}"#
        ))
        .unwrap();
        assert_eq!(
            key.api_url,
            "https://vpn.example.com:8443/AbC_def-1234567890"
        );
        assert_eq!(key.cert_sha256, pin.to_uppercase());
        assert_eq!(key.endpoint(), "vpn.example.com:8443");
        assert_eq!(format!("{key:?}"), "ManagementKey(..)");
        for url in [
            "http://1.2.3.4:1/abcdefghijklmnopq",
            "https://user:pw@1.2.3.4:1/abcdefghijklmnopq",
            "https://1.2.3.4:1/short",
            "https://1.2.3.4:1/abcdefghijklmnopq/extra",
            "https://1.2.3.4:1/abcdefghijklmnopq?x=1",
        ] {
            let text = format!(r#"{{"apiUrl":"{url}","certSha256":"{pin}"}}"#);
            assert!(ManagementKey::parse(&text).is_err(), "{url}");
        }
        let extra = format!(
            r#"{{"apiUrl":"https://1.2.3.4:1/abcdefghijklmnopq","certSha256":"{pin}","x":1}}"#
        );
        assert!(ManagementKey::parse(&extra).is_err());
    }

    #[test]
    fn operations_map_to_fixed_paths_only() {
        let op = ServerOp::KeyDelete {
            user: "1/../../server".into(),
            key: "2".into(),
        };
        assert!(request(&op).is_err());
        let op = ServerOp::KeyCreate {
            user: "12".into(),
            protocol: "openvpn".into(),
            import_as: None,
        };
        assert!(request(&op).is_err());
        let (method, path, body) = request(&ServerOp::KeyCreate {
            user: "12".into(),
            protocol: "amneziawg".into(),
            import_as: Some("home".into()),
        })
        .unwrap();
        assert_eq!((method, path.as_str()), (Method::POST, "/users/12/keys"));
        assert_eq!(body.unwrap(), json!({"protocol":"amneziawg"}));
    }
}
