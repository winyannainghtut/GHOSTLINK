//! Outline-compatible Shadowsocks access keys. Keys never implement a custom protocol.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose, Engine};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use url::Url;

// Deliberately not Debug or Serialize: credentials must never enter normal logs or responses.
pub struct AccessKey {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub label: Option<String>,
}

fn decode64(value: &str) -> Result<String> {
    let bytes = [
        general_purpose::URL_SAFE_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::STANDARD,
    ]
    .iter()
    .find_map(|engine| engine.decode(value).ok())
    .context("Invalid access key encoding")?;
    String::from_utf8(bytes).context("Access key must use UTF-8")
}
fn decode(value: &str) -> Result<String> {
    Ok(percent_decode_str(value)
        .decode_utf8()
        .context("Invalid access key text")?
        .into())
}

impl AccessKey {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(
            value.len() <= 16384 && value.starts_with("ss://"),
            "Paste a static Outline access key beginning with ss://"
        );
        let (main, fragment) = value.split_once('#').unwrap_or((value, ""));
        let label = if fragment.is_empty() {
            None
        } else {
            let label = decode(fragment)?;
            ensure!(valid_label(&label), "Invalid server name in access key");
            Some(label)
        };
        let raw = main.strip_prefix("ss://").unwrap();
        let normalized = if raw.contains('@') {
            main.to_string()
        } else {
            format!("ss://{}", decode64(raw.trim_end_matches('/'))?)
        };
        let url =
            Url::parse(&normalized).map_err(|_| anyhow::anyhow!("Malformed Outline access key"))?;
        ensure!(
            url.scheme() == "ss" && matches!(url.path(), "" | "/"),
            "Unsupported access key path"
        );
        for (name, value) in url.query_pairs() {
            ensure!(name == "outline" && value == "1", "Access key plugins, prefixes and custom transports are not supported in this build");
        }
        let credentials = match url.password() {
            Some(password) => format!("{}:{}", decode(url.username())?, decode(password)?),
            None => decode64(&decode(url.username())?)?,
        };
        let (method, password) = credentials
            .split_once(':')
            .context("Access key credentials are incomplete")?;
        ensure!(
            matches!(
                method,
                "chacha20-ietf-poly1305" | "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm"
            ),
            "This access key uses an unsupported or obsolete cipher"
        );
        ensure!(
            !password.is_empty()
                && password.len() <= 1024
                && !password.chars().any(char::is_control),
            "Invalid access key password"
        );
        let server = url
            .host_str()
            .context("Access key has no server")?
            .trim_matches(['[', ']'])
            .to_string();
        let port = url
            .port()
            .filter(|p| *p != 0)
            .context("Access key must include a valid port")?;
        ensure!(!server.is_empty(), "Access key has no server");
        Ok(Self {
            server,
            port,
            method: method.into(),
            password: password.into(),
            label,
        })
    }
    pub fn summary(&self, name: &str, source: &str) -> crate::profile::ProfileSummary {
        use sha2::{Digest, Sha256};
        crate::profile::ProfileSummary {
            name: name.into(),
            kind: "outline".into(),
            display_name: self.label.clone().unwrap_or_else(|| name.into()),
            remotes: vec![crate::profile::Remote {
                host: self.server.clone(),
                port: self.port,
                protocol: "shadowsocks".into(),
            }],
            tunnel_mode: "full".into(),
            certificate_expires_unix: None,
            // Fingerprint contains no reversible access credential.
            sha256: hex::encode(Sha256::digest(source.as_bytes())),
            is_default: false,
        }
    }
}
pub fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= 80 && !value.chars().any(char::is_control)
}

pub async fn resolve(source: &str) -> Result<AccessKey> {
    let source = source.trim();
    if source.starts_with("ss://") {
        return AccessKey::parse(source);
    }
    ensure!(
        source.len() <= 16384 && source.starts_with("ssconf://"),
        "Use an ss:// or ssconf:// Outline access key"
    );
    let mut url = Url::parse(&source.replacen("ssconf://", "https://", 1))
        .map_err(|_| anyhow::anyhow!("Malformed dynamic access key"))?;
    let label = url.fragment().map(decode).transpose()?;
    url.set_fragment(None);
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Dynamic key URLs cannot contain HTTP credentials"
    );
    let host = url
        .host_str()
        .context("Dynamic key has no hostname")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = url
        .port_or_known_default()
        .context("Invalid dynamic key port")?;
    let addresses: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .context("Dynamic key DNS timed out")??
    .collect();
    ensure!(
        !addresses.is_empty() && addresses.iter().all(|a| is_public(a.ip())),
        "Dynamic keys must use public HTTPS servers; local and private destinations are blocked"
    );
    // Resolve once, validate, and pin: redirects and DNS rebinding cannot target local services.
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(&host, &addresses)
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Unable to retrieve dynamic access key over HTTPS"))?;
    ensure!(
        response.status().is_success(),
        "Dynamic access key server returned an error"
    );
    let mut bytes = vec![];
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("Dynamic key transfer failed"))?
    {
        ensure!(
            bytes.len() + chunk.len() <= 65536,
            "Dynamic key configuration is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(bytes).context("Dynamic key must be UTF-8")?;
    let mut key = if text.trim().starts_with("ss://") {
        AccessKey::parse(text.trim())?
    } else {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            server: String,
            server_port: u16,
            method: String,
            password: String,
        }
        let config: Config = serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("Only static ss:// and legacy JSON dynamic keys are supported; advanced YAML keys are not supported"))?;
        let credentials = general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{}:{}", config.method, config.password));
        let endpoint = if config.server.contains(':') {
            format!("[{}]", config.server)
        } else {
            config.server
        };
        AccessKey::parse(&format!(
            "ss://{credentials}@{endpoint}:{}",
            config.server_port
        ))?
    };
    if let Some(label) = label {
        ensure!(valid_label(&label), "Invalid server name");
        key.label = Some(label);
    }
    Ok(key)
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && matches!(o[1], 18 | 19))
                || (o[0] == 192 && o[1] == 0 && matches!(o[2], 0 | 2))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            // Public global unicast only; exclude translation, ULA, link-local and documentation.
            (ip.segments()[0] & 0xe000 == 0x2000)
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_outline_sip002_and_legacy_keys() {
        let credential =
            general_purpose::URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:secret-with:colon");
        let key = AccessKey::parse(&format!(
            "ss://{credential}@example.com:443/?outline=1#My%20Server"
        ))
        .unwrap();
        assert_eq!(key.password, "secret-with:colon");
        assert_eq!(key.label.as_deref(), Some("My Server"));
        let legacy = general_purpose::STANDARD.encode("aes-256-gcm:secret@example.com:443");
        assert_eq!(
            AccessKey::parse(&format!("ss://{legacy}")).unwrap().port,
            443
        );
        assert_eq!(
            AccessKey::parse("ss://aes-128-gcm:s%40cret@[2001:db8::1]:443")
                .unwrap()
                .password,
            "s@cret"
        );
    }
    #[test]
    fn obsolete_and_executable_options_are_rejected() {
        for key in [
            "ss://aes-256-cfb:secret@example.com:443",
            "ss://none:secret@example.com:443",
            "ss://aes-256-gcm:secret@example.com:443?plugin=exec",
            "ss://aes-256-gcm:secret@example.com:0",
        ] {
            assert!(AccessKey::parse(key).is_err());
        }
    }
    #[test]
    fn dynamic_keys_cannot_reach_private_services() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(address.parse().unwrap()));
        }
        assert!(is_public("1.1.1.1".parse().unwrap()));
    }
}
