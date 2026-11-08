use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::prelude::FromDer;

pub const MAX_PROFILE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub name: String,
    #[serde(default = "openvpn_kind")]
    pub kind: String,
    #[serde(default)]
    pub display_name: String,
    pub remotes: Vec<Remote>,
    pub tunnel_mode: String,
    pub certificate_expires_unix: Option<i64>,
    pub sha256: String,
    pub is_default: bool,
}
fn openvpn_kind() -> String {
    "openvpn".into()
}

pub struct ValidatedProfile {
    pub canonical: String,
    pub summary: ProfileSummary,
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn port(value: &str) -> Result<u16> {
    let p = value.parse::<u16>().context("Invalid remote port")?;
    ensure!(p != 0, "Remote port must be nonzero");
    Ok(p)
}

/// A client transport. `tcp`, `tcp4` and `tcp6` are how most profiles spell the `-client` forms
/// (the canonical profile is always a client), and are written in that form.
fn protocol(value: &str) -> Result<&'static str> {
    Ok(match value {
        "udp" => "udp",
        "udp4" => "udp4",
        "udp6" => "udp6",
        "tcp" | "tcp-client" => "tcp-client",
        "tcp4" | "tcp4-client" => "tcp4-client",
        "tcp6" | "tcp6-client" => "tcp6-client",
        _ => bail!("Only UDP or TCP client transport is allowed"),
    })
}

pub fn validate(name: &str, input: &str) -> Result<ValidatedProfile> {
    use sha2::{Digest, Sha256};
    ensure!(
        valid_name(name),
        "Profile name must contain 1-64 ASCII letters, digits, hyphens or underscores"
    );
    ensure!(input.len() <= MAX_PROFILE, "Profile exceeds 1 MiB");
    ensure!(
        !input
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        "Profile contains control characters"
    );
    let mut blocks = BTreeMap::<String, String>::new();
    let mut current: Option<String> = None;
    let mut directives = Vec::<(String, Vec<String>)>::new();
    for raw in input.lines() {
        let line = raw.trim();
        if let Some(tag) = current.as_ref() {
            if line == format!("</{tag}>") {
                current = None;
            } else {
                ensure!(
                    !line.contains(['<', '>']),
                    "Nested inline blocks are forbidden"
                );
                blocks.get_mut(tag).unwrap().push_str(line);
                blocks.get_mut(tag).unwrap().push('\n');
            }
            continue;
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('<') {
            let tag = line
                .strip_prefix('<')
                .and_then(|x| x.strip_suffix('>'))
                .context("Malformed inline block")?;
            ensure!(
                matches!(
                    tag,
                    "ca" | "cert" | "key" | "tls-crypt" | "tls-crypt-v2" | "tls-auth"
                ),
                "Unsupported inline block"
            );
            ensure!(!blocks.contains_key(tag), "Duplicate inline block");
            blocks.insert(tag.into(), String::new());
            current = Some(tag.into());
            continue;
        }
        // A deliberately narrow grammar. Canonical output never interprets shell or config escapes.
        ensure!(!line.contains(['\\', '"', '\'', '#', ';']), "Quoted, escaped and trailing-comment directives are unsupported; use simple inline profiles");
        let mut words = line.split_ascii_whitespace();
        let key = words.next().unwrap();
        let args: Vec<String> = words.map(String::from).collect();
        directives.push((key.into(), args));
    }
    ensure!(current.is_none(), "Unterminated inline block");
    for tag in ["ca", "cert", "key"] {
        ensure!(
            blocks.contains_key(tag),
            "Inline {tag} is required; external file references are forbidden"
        );
    }
    ensure!(
        !blocks["key"].contains("ENCRYPTED"),
        "Encrypted private keys require an OS vault workflow not yet supported"
    );
    // `openssl ecparam -genkey` writes an EC PARAMETERS block before the key. OpenVPN skips it
    // when it loads the key, so it may stay; exactly one private key is required.
    let key_blocks = pem::parse_many(&blocks["key"]).context("Invalid PEM private key")?;
    let keys: Vec<_> = key_blocks
        .iter()
        .filter(|block| block.tag() != "EC PARAMETERS")
        .collect();
    ensure!(
        keys.len() == 1
            && matches!(
                keys[0].tag(),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
            ),
        "Unsupported private key format"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut expires = i64::MAX;
    for tag in ["ca", "cert"] {
        let certs = pem::parse_many(&blocks[tag]).context("Invalid certificate PEM")?;
        ensure!(!certs.is_empty(), "Empty certificate block");
        for cert in certs {
            ensure!(
                cert.tag() == "CERTIFICATE",
                "Only certificates may appear in certificate blocks"
            );
            let (_, x509) = x509_parser::certificate::X509Certificate::from_der(cert.contents())
                .map_err(|_| anyhow::anyhow!("Invalid X.509 certificate"))?;
            let validity = x509.validity();
            ensure!(
                validity.not_before.timestamp() <= now,
                "Certificate is not yet valid"
            );
            ensure!(
                validity.not_after.timestamp() > now,
                "Certificate has expired"
            );
            expires = expires.min(validity.not_after.timestamp());
        }
    }
    let mut proto = "udp".to_string();
    let mut default_port = 1194;
    let mut full = false;
    // Kept as the profile gives them: `auth` is also the tls-auth HMAC digest, which must match
    // the server, and the redirect flags change which traffic the tunnel takes.
    let mut digest = "SHA256".to_string();
    let mut redirect_flags = vec![];
    let mut remote_args = vec![];
    let mut extra = String::new();
    let mut seen = std::collections::HashSet::new();
    for (key, args) in &directives {
        if !matches!(
            key.as_str(),
            "remote" | "route" | "route-ipv6" | "dhcp-option"
        ) {
            ensure!(seen.insert(key), "Duplicate directive: {key}");
        }
        let one = || -> Result<&str> {
            ensure!(args.len() == 1, "{key} requires one value");
            Ok(args[0].as_str())
        };
        let zero = || -> Result<()> {
            ensure!(args.is_empty(), "{key} does not accept arguments");
            Ok(())
        };
        match key.as_str() {
            "client" | "nobind" | "persist-key" | "persist-tun" | "auth-nocache" | "remote-random" | "route-nopull" => { zero()?; if matches!(key.as_str(), "remote-random" | "route-nopull") { extra.push_str(&format!("{key}\n")); } }
            "dev" => ensure!(one()? == "tun", "Only TUN mode is supported"),
            "proto" => proto = protocol(one()?)?.into(),
            "port" | "rport" => default_port = port(one()?)?,
            "remote" => { ensure!((1..=3).contains(&args.len()), "remote requires host, optional port and protocol"); remote_args.push(args); }
            "remote-cert-tls" => ensure!(one()? == "server", "Server certificate verification cannot be disabled"),
            "tls-version-min" => ensure!(matches!(one()?, "1.2" | "1.3"), "TLS 1.2 or newer is required"),
            "cipher" | "data-ciphers" => ensure!(one()?.split(':').all(|c| matches!(c, "AES-256-GCM" | "AES-128-GCM" | "CHACHA20-POLY1305")), "Only modern AEAD ciphers are supported"),
            "auth" => { let value = one()?; ensure!(matches!(value, "SHA256" | "SHA384" | "SHA512"), "Weak digest rejected"); digest = value.into(); }
            "allow-compression" => ensure!(one()? == "no", "Compression is forbidden"),
            "redirect-gateway" => {
                ensure!(args.iter().all(|a| matches!(a.as_str(), "def1" | "ipv6" | "bypass-dhcp" | "block-local")), "Unsupported redirect-gateway option");
                full = true;
                // def1 is always written; the others in a fixed order, once each.
                redirect_flags = ["ipv6", "bypass-dhcp", "block-local"].into_iter().filter(|flag| args.iter().any(|a| a == flag)).collect();
            }
            "route" => {
                ensure!((1..=4).contains(&args.len()), "Invalid IPv4 route");
                args[0].parse::<std::net::Ipv4Addr>().context("Routes must use numeric IPv4 addresses")?;
                if args.len() >= 2 { args[1].parse::<std::net::Ipv4Addr>().context("Invalid IPv4 netmask")?; }
                if args.len() >= 3 && !matches!(args[2].as_str(), "vpn_gateway" | "net_gateway") { args[2].parse::<std::net::Ipv4Addr>().context("Invalid route gateway")?; }
                if args.len() == 4 { args[3].parse::<u16>().context("Invalid route metric")?; }
                extra.push_str(&format!("route {}\n", args.join(" ")));
            }
            "dhcp-option" => {
                ensure!(args.len() == 2 && args[0] == "DNS", "Only numeric DNS options are supported");
                args[1].parse::<std::net::IpAddr>().context("Invalid DNS address")?;
                extra.push_str(&format!("dhcp-option DNS {}\n", args[1]));
            }
            "verify-x509-name" => {
                ensure!(args.len() == 2 && args[1] == "name" && valid_hostname(&args[0]), "Use verify-x509-name HOST name");
                extra.push_str(&format!("verify-x509-name {} name\n", args[0]));
            }
            "key-direction" => { ensure!(one()? == "1", "Client tls-auth key direction must be 1"); extra.push_str("key-direction 1\n"); }
            "verb" => ensure!(matches!(one()?, "0" | "1" | "2" | "3"), "Verbose logging is forbidden"),
            "resolv-retry" => { let value = one()?; ensure!(value == "infinite" || value.parse::<u16>().is_ok(), "Invalid resolver retry"); }
            "ping" | "ping-restart" | "connect-timeout" | "connect-retry-max" | "tun-mtu" => {
                let n = one()?.parse::<u16>().context("Invalid numeric option")?;
                ensure!(n > 0 && (key != "tun-mtu" || (576..=9000).contains(&n)), "Numeric option outside supported range");
                extra.push_str(&format!("{key} {n}\n"));
            }
            _ => bail!("Profile contains a forbidden or unsupported directive (scripts, paths, authentication prompts and unknown options are rejected)"),
        }
    }
    ensure!(
        !remote_args.is_empty() && remote_args.len() <= 16,
        "One to sixteen remote endpoints are required"
    );
    ensure!(
        !(full && seen.iter().any(|x| x.as_str() == "route-nopull")),
        "Full tunnel and route-nopull conflict"
    );
    let mut canonical = format!("client\ndev tun\nnobind\nremote-cert-tls server\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nauth {digest}\nallow-compression no\nauth-nocache\nscript-security 1\nverb 3\nresolv-retry infinite\nconnect-retry 2 30\n");
    // Do not weaken an explicitly stricter TLS minimum.
    if directives
        .iter()
        .any(|(k, a)| k == "tls-version-min" && a == &["1.3"])
    {
        canonical = canonical.replace("tls-version-min 1.2", "tls-version-min 1.3");
    }
    canonical.push_str(&extra);
    let mut remotes = vec![];
    for args in remote_args {
        ensure!(
            valid_hostname(&args[0]),
            "Invalid remote hostname or IP address"
        );
        let p = if args.len() >= 2 {
            port(&args[1])?
        } else {
            default_port
        };
        let transport = if args.len() == 3 {
            protocol(&args[2])?
        } else {
            &proto
        };
        canonical.push_str(&format!("remote {} {p} {transport}\n", args[0]));
        remotes.push(Remote {
            host: args[0].clone(),
            port: p,
            protocol: transport.into(),
        });
    }
    ensure!(remotes.iter().all(|remote| remote.protocol == remotes[0].protocol), "Use separate profiles for different remote transports so connection protocol is unambiguous");
    // Pull only the selected route mode. The service does not claim platform leak prevention.
    if full {
        canonical.push_str(&format!(
            "{}\n",
            ["redirect-gateway", "def1"]
                .into_iter()
                .chain(redirect_flags)
                .collect::<Vec<_>>()
                .join(" ")
        ));
    } else {
        canonical.push_str("pull-filter ignore redirect-gateway\n");
    }
    for (tag, content) in blocks {
        canonical.push_str(&format!("<{tag}>\n{content}</{tag}>\n"));
    }
    let sha256 = hex::encode(Sha256::digest(canonical.as_bytes()));
    Ok(ValidatedProfile {
        canonical,
        summary: ProfileSummary {
            name: name.into(),
            kind: "openvpn".into(),
            display_name: name.into(),
            remotes,
            tunnel_mode: if full { "full" } else { "split" }.into(),
            certificate_expires_unix: Some(expires),
            sha256,
            is_default: false,
        },
    })
}

fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with(['-', '.'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_names_rejected() {
        for s in ["../x", "a/b", "a\\b", "", ".", "x y"] {
            assert!(!valid_name(s));
        }
    }
    /// A valid inline profile with a fresh self-signed certificate; `key` replaces the key block.
    fn profile(extra: &str, key: Option<&str>) -> String {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["ghostlink-test".into()])
            .unwrap()
            .self_signed(&pair)
            .unwrap()
            .pem();
        let key = key
            .map(String::from)
            .unwrap_or_else(|| pair.serialize_pem());
        format!("client\ndev tun\nremote 192.0.2.10 1194\n{extra}<ca>\n{cert}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n")
    }

    #[test]
    fn profile_choices_reach_the_canonical_profile() {
        let digest = validate("t", &profile("auth SHA512\n", None)).unwrap();
        assert!(digest.canonical.contains("\nauth SHA512\n"));
        assert!(!digest.canonical.contains("\nauth SHA256\n"));
        assert!(validate("t", &profile("", None))
            .unwrap()
            .canonical
            .contains("\nauth SHA256\n"));
        let redirect = validate(
            "t",
            &profile("redirect-gateway block-local def1 ipv6\n", None),
        )
        .unwrap();
        assert!(redirect
            .canonical
            .contains("\nredirect-gateway def1 ipv6 block-local\n"));
        assert_eq!(redirect.summary.tunnel_mode, "full");
        assert!(validate("t", &profile("redirect-gateway local\n", None)).is_err());
    }

    #[test]
    fn plain_tcp_means_a_tcp_client() {
        let tcp = validate("t", &profile("proto tcp\n", None)).unwrap();
        assert!(tcp
            .canonical
            .contains("\nremote 192.0.2.10 1194 tcp-client\n"));
        assert_eq!(tcp.summary.remotes[0].protocol, "tcp-client");
        let both = profile("proto tcp4\n", None).replace(
            "remote 192.0.2.10 1194\n",
            "remote 192.0.2.10 1194\nremote 192.0.2.11 443 tcp4\n",
        );
        assert_eq!(validate("t", &both).unwrap().summary.remotes.len(), 2);
        for bad in ["proto tcp-server\n", "proto tls\n"] {
            assert!(validate("t", &profile(bad, None)).is_err(), "{bad}");
        }
    }

    #[test]
    fn ec_keys_with_their_parameters_block_are_accepted() {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let sec1 = pair
            .serialize_pem()
            .replace("PRIVATE KEY", "EC PRIVATE KEY");
        let parameters =
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n";
        let with = validate("t", &profile("", Some(&format!("{parameters}{sec1}")))).unwrap();
        assert!(with.canonical.contains("EC PARAMETERS"));
        for bad in [parameters.to_string(), format!("{sec1}{sec1}")] {
            let error = validate("t", &profile("", Some(&bad))).err().unwrap();
            assert_eq!(error.to_string(), "Unsupported private key format");
        }
    }

    #[test]
    fn executable_directives_and_missing_certificates_fail() {
        for s in [
            "up evil.exe",
            "plugin exploit.dll",
            "config elsewhere",
            "<ca>\n</ca>\n",
            "management 0.0.0.0 9000",
            "auth-user-pass secrets.txt",
        ] {
            assert!(validate("test", s).is_err());
        }
    }
}
