//! Client split tunneling: validation and the sing-box route/DNS rules it produces.
use crate::wireguard;
use anyhow::{ensure, Context, Result};
use ghostlink_contracts::{RoutingPolicy, SplitMode};
use serde_json::{json, Value};

const MAX_ENTRIES: usize = 512;
const MAX_APPS: usize = 128;

/// Normalizes `example.com`, `.example.com` or `*.example.com` to a lowercase suffix.
fn domain(value: &str) -> Result<String> {
    let value = value
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        "Invalid site {value:?}: use a domain such as example.com"
    );
    Ok(value)
}

fn app(value: &str) -> Result<String> {
    let value = value.trim();
    ensure!(
        !value.is_empty() && value.len() <= 260 && !value.chars().any(char::is_control),
        "Invalid app {value:?}: use an executable name or full path"
    );
    Ok(value.to_string())
}

fn is_path(app: &str) -> bool {
    app.contains(['/', '\\'])
}

/// Validates and normalizes a policy; duplicates are removed and order is kept.
pub fn validate(policy: &RoutingPolicy) -> Result<RoutingPolicy> {
    ensure!(
        policy.domains.len() <= MAX_ENTRIES && policy.ip_ranges.len() <= MAX_ENTRIES,
        "At most {MAX_ENTRIES} sites and {MAX_ENTRIES} IP ranges are supported"
    );
    ensure!(
        policy.apps.len() <= MAX_APPS,
        "At most {MAX_APPS} apps are supported"
    );
    let mut normalized = RoutingPolicy {
        mode: policy.mode,
        lan_direct: policy.lan_direct,
        ..Default::default()
    };
    for item in &policy.domains {
        let item = domain(item)?;
        if !normalized.domains.contains(&item) {
            normalized.domains.push(item);
        }
    }
    for item in &policy.ip_ranges {
        let item =
            wireguard::prefix(item.trim()).with_context(|| format!("Invalid IP range {item:?}"))?;
        if !normalized.ip_ranges.contains(&item) {
            normalized.ip_ranges.push(item);
        }
    }
    for item in &policy.apps {
        let item = app(item)?;
        if !normalized.apps.contains(&item) {
            normalized.apps.push(item);
        }
    }
    if normalized.mode == SplitMode::Only {
        ensure!(
            !(normalized.domains.is_empty()
                && normalized.ip_ranges.is_empty()
                && normalized.apps.is_empty()),
            "\"Only these\" needs at least one site, IP range or app"
        );
    }
    Ok(normalized)
}

/// Rules for one target outbound: one rule per matcher kind (sing-box ORs within a field).
fn matchers(policy: &RoutingPolicy, target: &str) -> Vec<Value> {
    let mut rules = vec![];
    let (paths, names): (Vec<&String>, Vec<&String>) = policy.apps.iter().partition(|a| is_path(a));
    if !names.is_empty() {
        rules.push(json!({"process_name":names,"outbound":target}));
    }
    if !paths.is_empty() {
        rules.push(json!({"process_path":paths,"outbound":target}));
    }
    if !policy.domains.is_empty() {
        rules.push(json!({"domain_suffix":policy.domains,"outbound":target}));
    }
    if !policy.ip_ranges.is_empty() {
        rules.push(json!({"ip_cidr":policy.ip_ranges,"outbound":target}));
    }
    rules
}

pub struct Rendered {
    /// Route rules to append after the fixed sniff/DNS/health rules.
    pub route_rules: Vec<Value>,
    /// DNS rules (bypassed sites resolve locally; in "only" mode, listed sites through the VPN).
    pub dns_rules: Vec<Value>,
    pub route_final: &'static str,
    pub dns_final: &'static str,
    pub needs_direct: bool,
    pub find_process: bool,
}

/// `proxy` is the tunnel outbound tag; `direct` and the DNS server tags are fixed by the caller.
pub fn render(policy: &RoutingPolicy, proxy: &'static str) -> Rendered {
    let mut route_rules = vec![];
    let mut dns_rules = vec![];
    let (route_final, dns_final) = match policy.mode {
        SplitMode::Full | SplitMode::Bypass => (proxy, "vpn-dns"),
        SplitMode::Only => ("direct", "bootstrap"),
    };
    match policy.mode {
        SplitMode::Full => {}
        SplitMode::Bypass => {
            route_rules.extend(matchers(policy, "direct"));
            if !policy.domains.is_empty() {
                dns_rules.push(json!({"domain_suffix":policy.domains,"server":"bootstrap"}));
            }
        }
        SplitMode::Only => {
            route_rules.extend(matchers(policy, proxy));
            if !policy.domains.is_empty() {
                dns_rules.push(json!({"domain_suffix":policy.domains,"server":"vpn-dns"}));
            }
        }
    }
    if policy.lan_direct && policy.mode != SplitMode::Only {
        route_rules.push(json!({"ip_is_private":true,"outbound":"direct"}));
    }
    Rendered {
        needs_direct: route_final == "direct"
            || route_rules.iter().any(|r| r["outbound"] == "direct"),
        // Process lookups cost CPU on every connection; full mode keeps its apps list but uses
        // no app rules.
        find_process: policy.mode != SplitMode::Full && !policy.apps.is_empty(),
        route_rules,
        dns_rules,
        route_final,
        dns_final,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: SplitMode) -> RoutingPolicy {
        RoutingPolicy {
            mode,
            domains: vec![
                "*.Example.com".into(),
                "example.com".into(),
                "bank.example".into(),
            ],
            ip_ranges: vec!["192.168.10.0/24".into(), "2001:db8::/32".into()],
            apps: vec!["chrome.exe".into(), r"C:\Games\game.exe".into()],
            lan_direct: true,
        }
    }

    #[test]
    fn policies_normalize_and_reject_bad_entries() {
        let p = validate(&policy(SplitMode::Bypass)).unwrap();
        assert_eq!(p.domains, ["example.com", "bank.example"]);
        assert_eq!(p.ip_ranges, ["192.168.10.0/24", "2001:db8::/32"]);
        for bad in [
            RoutingPolicy {
                domains: vec!["exa mple.com".into()],
                ..Default::default()
            },
            RoutingPolicy {
                domains: vec!["http://example.com/path".into()],
                ..Default::default()
            },
            RoutingPolicy {
                ip_ranges: vec!["10.0.0.0/33".into()],
                ..Default::default()
            },
            RoutingPolicy {
                apps: vec!["evil\napp".into()],
                ..Default::default()
            },
            RoutingPolicy {
                mode: SplitMode::Only,
                ..Default::default()
            },
            RoutingPolicy {
                domains: vec!["a.com".into(); 513],
                ..Default::default()
            },
        ] {
            assert!(validate(&bad).is_err());
        }
    }

    #[test]
    fn bypass_sends_listed_items_direct_and_resolves_them_locally() {
        let r = render(&validate(&policy(SplitMode::Bypass)).unwrap(), "proxy");
        assert_eq!(r.route_final, "proxy");
        assert!(r.find_process && r.needs_direct);
        assert_eq!(r.route_rules[0]["process_name"][0], "chrome.exe");
        assert_eq!(r.route_rules[1]["process_path"][0], r"C:\Games\game.exe");
        assert!(r
            .route_rules
            .iter()
            .all(|rule| rule["outbound"] == "direct"));
        assert_eq!(r.route_rules.last().unwrap()["ip_is_private"], true);
        assert_eq!(r.dns_rules[0]["server"], "bootstrap");
    }

    #[test]
    fn only_mode_inverts_routing_and_full_adds_nothing() {
        let r = render(&validate(&policy(SplitMode::Only)).unwrap(), "proxy");
        assert_eq!(r.route_final, "direct");
        assert_eq!(r.dns_final, "bootstrap");
        assert!(r.route_rules.iter().all(|rule| rule["outbound"] == "proxy"));
        let full = render(&RoutingPolicy::default(), "proxy");
        assert!(full.route_rules.is_empty() && !full.needs_direct && full.route_final == "proxy");
        // A full policy that still lists apps from an earlier mode looks up no processes.
        let kept = render(&validate(&policy(SplitMode::Full)).unwrap(), "proxy");
        assert!(!kept.find_process);
        assert!(kept
            .route_rules
            .iter()
            .all(|rule| rule.get("process_name").is_none()));
    }
}
