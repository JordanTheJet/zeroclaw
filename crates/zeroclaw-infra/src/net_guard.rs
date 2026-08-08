//! Network-safety primitives shared across crates that must reject SSRF and
//! local/private targets. Lives in `zeroclaw-infra` so both the tool layer
//! (`zeroclaw-tools` domain guard) and the plugin host (`zeroclaw-plugins`
//! `wasi:http` egress) read one implementation without a tool-to-plugin
//! dependency.
//!
//! Everything here operates on plain data — host strings, IP addresses, and
//! pattern lists — so no consumer needs a tool-specific or config-specific
//! type to ask "may this process reach that destination". DNS resolution is
//! deliberately *not* part of this module: callers resolve, then hand the
//! resolved addresses here for validation.
//!
//! The pieces are:
//!
//! - [`normalize_domain`] / [`normalize_allowed_domains`]: turn operator-authored
//!   allowlist entries into canonical bare hosts.
//! - [`host_matches_allowlist`]: match a request host against those entries.
//! - [`is_cloud_metadata_ip`], [`is_private_or_local_host`], [`is_non_global_v4`],
//!   [`is_non_global_v6`]: address-class classification.
//! - [`validate_resolved_ips_are_public`] /
//!   [`validate_resolved_ips_exclude_metadata`]: post-resolution SSRF checks.

// ── allowlist normalization ───────────────────────────────────────
// Operator-authored entries may be written as bare hosts, bracketed IPv6,
// or full URLs; normalization reduces them all to a canonical lowercase
// bare host so matching never has to re-parse.

/// Normalize a single allowlist entry to a canonical bare host.
///
/// Accepts bare hosts, bare IPv4/IPv6 literals (bracketed or not), and full
/// URLs (a missing scheme is treated as `https://`). Returns `None` for empty
/// input, input containing whitespace, unmatched brackets, entries carrying
/// userinfo, or anything that does not parse to a host.
#[must_use]
pub fn normalize_domain(raw: &str) -> Option<String> {
    let input = raw.trim();
    if input.is_empty() || input.chars().any(char::is_whitespace) {
        return None;
    }

    let bare_ip = match (input.starts_with('['), input.ends_with(']')) {
        (true, true) => &input[1..input.len() - 1],
        (false, false) => input,
        _ => return None,
    };
    if let Ok(ip) = bare_ip.parse::<std::net::IpAddr>() {
        return Some(ip.to_string().to_lowercase());
    }

    let parsed = url::Url::parse(input)
        .or_else(|_| url::Url::parse(&format!("https://{input}")))
        .ok()?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }

    let host = parsed.host_str()?;
    let trimmed = host.trim();
    let host_no_brackets = match (trimmed.starts_with('['), trimmed.ends_with(']')) {
        (true, true) => &trimmed[1..trimmed.len() - 1],
        (false, false) => trimmed,
        _ => return None,
    };
    let normalized = host_no_brackets
        .trim_start_matches('.')
        .trim_end_matches('.');
    if normalized.is_empty() {
        return None;
    }

    Some(normalized.to_lowercase())
}

/// Normalize a whole allowlist, sorted and deduplicated.
///
/// `label` names the configuration surface in the error message so the
/// operator can find the offending entry (for example
/// `"http_request.allowed_domains"`). Fails if any entry is not a valid
/// domain, hostname, IPv4, or IPv6 address.
///
/// # Errors
///
/// Returns an error naming every rejected entry when one or more entries
/// fail [`normalize_domain`].
pub fn normalize_allowed_domains(domains: Vec<String>, label: &str) -> anyhow::Result<Vec<String>> {
    let mut rejected = Vec::new();
    let mut normalized = domains
        .into_iter()
        .filter_map(|d| {
            normalize_domain(&d).or_else(|| {
                rejected.push(d.clone());
                None
            })
        })
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        anyhow::bail!(
            "Invalid {label} entry(s): [{}]. Each entry must be a valid domain, hostname, IPv4, or IPv6 address.",
            rejected.join(", ")
        );
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

// ── host matching ─────────────────────────────────────────────────

/// True when `host` matches any entry in a normalized `allowed` list.
///
/// Matching rules, unchanged from the tool-layer original:
/// - a bare `*` entry matches everything;
/// - a `*.example.com` entry matches `example.com` and any subdomain;
/// - an IP entry, or an IP host, matches only exactly;
/// - a bare domain entry matches itself and any subdomain of it.
///
/// These are the permissive semantics the tool-layer `allowed_domains` lists
/// have always used. A consumer that needs stricter rules — no bare `*`, no
/// implicit subdomains — must enforce that when it validates its own entries,
/// or use a separate matcher; this function will not reject them.
#[must_use]
pub fn host_matches_allowlist(host: &str, allowed: &[String]) -> bool {
    if allowed.iter().any(|d| d == "*") {
        return true;
    }

    let host_is_ip = host.parse::<std::net::IpAddr>().is_ok();

    allowed.iter().any(|pattern| {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".example.com"
            return host.ends_with(suffix) || host == &pattern[2..];
        }

        if host_is_ip || pattern.parse::<std::net::IpAddr>().is_ok() {
            return host == pattern;
        }

        host == pattern
            || host
                .strip_suffix(pattern)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

// ── address-class classification ──────────────────────────────────

/// True when `host` is loopback, private, link-local, a documentation/
/// benchmark range, or one of the `localhost` / `*.local` name forms. Accepts
/// bracketed IPv6 (`[::1]`) and is case-insensitive.
#[must_use]
pub fn is_private_or_local_host(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase();

    if &bare == "localhost" || bare.ends_with(".localhost") {
        return true;
    }

    if bare
        .rsplit('.')
        .next()
        .is_some_and(|label| label == "local")
    {
        return true;
    }

    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => is_non_global_v4(v4),
            std::net::IpAddr::V6(v6) => is_non_global_v6(v6),
        };
    }

    false
}

/// True when an IPv4 address is not globally routable (loopback, RFC 1918,
/// link-local, CGNAT, documentation, benchmarking, reserved, multicast).
///
/// The classification follows the
/// [IANA IPv4 Special-Purpose Address Registry][iana-v4]. Deprecated
/// translation space is rejected conservatively even where the registry no
/// longer assigns a global-reachability value.
///
/// [iana-v4]: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
#[must_use]
pub fn is_non_global_v4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, c, d] = v4.octets();
    a == 0 // 0.0.0.0/8 ("This network")
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || (a == 100 && (64..=127).contains(&b)) // RFC 6598 shared address space
        || a >= 240 // Reserved
        || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
        || (a == 192 && b == 0 && c == 2) // Documentation (192.0.2.0/24)
        || (a == 192 && b == 88 && c == 99) // Deprecated 6to4 relay anycast
        || (a == 198 && b == 51 && c == 100) // Documentation (198.51.100.0/24)
        || (a == 203 && b == 0 && c == 113) // Documentation (203.0.113.0/24)
        || (a == 198 && (18..=19).contains(&b)) // Benchmarking (198.18.0.0/15)
}

/// True when an IPv6 address is not globally routable (loopback, ULA,
/// link-local, site-local, documentation, multicast, unallocated/reserved,
/// or an IPv4-embedded non-global v4).
///
/// IANA currently allocates [global IPv6 unicast addresses][iana-v6-space]
/// from `2000::/3`.
/// This classifier additionally handles the globally reachable NAT64
/// well-known prefix and the more-specific exceptions in the
/// [IANA IPv6 Special-Purpose Address Registry][iana-v6-special]. Everything
/// else defaults closed.
///
/// [iana-v6-space]: https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
/// [iana-v6-special]: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
#[must_use]
pub fn is_non_global_v6(v6: std::net::Ipv6Addr) -> bool {
    let segs = v6.segments();

    // IPv4-mapped addresses and the NAT64 well-known /96 reach the embedded
    // IPv4 destination, so classify that effective destination rather than
    // accepting an encoded private address or rejecting an encoded public one.
    if let Some(v4) = embedded_ipv4(v6) {
        return is_non_global_v4(v4);
    }

    // IANA currently assigns global IPv6 unicast space only from 2000::/3.
    // The one globally reachable special prefix outside it (64:ff9b::/96) was
    // handled as an IPv4-embedded address above.
    if (segs[0] & 0xe000) != 0x2000 {
        return true;
    }

    let ietf_protocol_assignments = segs[0] == 0x2001 && segs[1] < 0x0200;
    // IANA marks these exact anycast assignments globally reachable. Keep
    // them distinct from the enclosing non-global 2001::/23 allocation.
    let globally_reachable_ietf_exception = matches!(
        u128::from_be_bytes(v6.octets()),
        0x2001_0001_0000_0000_0000_0000_0000_0001..=0x2001_0001_0000_0000_0000_0000_0000_0003
    ) || segs[0] == 0x2001 && segs[1] == 0x0003
        || segs[0] == 0x2001 && segs[1] == 0x0004 && segs[2] == 0x0112
        || segs[0] == 0x2001 && (0x0020..=0x003f).contains(&segs[1]);

    (ietf_protocol_assignments && !globally_reachable_ietf_exception)
        || segs[0] == 0x2002 // 6to4: global reachability is not guaranteed
        || (segs[0] == 0x2001 && segs[1] == 0x0db8) // Documentation (2001:db8::/32)
        || (segs[0] == 0x3fff && (segs[1] & 0xf000) == 0) // Documentation (3fff::/20)
}

const ALIBABA_METADATA_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 100, 100, 200);
const AZURE_PLATFORM_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(168, 63, 129, 16);
const GCP_METADATA_V6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }

    match v6.segments() {
        // RFC 6052 well-known prefix 64:ff9b::/96.
        [0x0064, 0xff9b, 0, 0, 0, 0, high, low] => {
            let [a, b] = high.to_be_bytes();
            let [c, d] = low.to_be_bytes();
            Some(std::net::Ipv4Addr::new(a, b, c, d))
        }
        _ => None,
    }
}

fn metadata_embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = embedded_ipv4(v6) {
        return Some(v4);
    }

    match v6.segments() {
        // Deprecated IPv4-compatible form ::a.b.c.d.
        [0, 0, 0, 0, 0, 0, high, low]
        // 6to4 embeds the effective IPv4 next hop after 2002::/16.
        | [0x2002, high, low, _, _, _, _, _] => {
            let [a, b] = high.to_be_bytes();
            let [c, d] = low.to_be_bytes();
            Some(std::net::Ipv4Addr::new(a, b, c, d))
        }
        _ => None,
    }
}

/// True when `ip` is a known cloud instance-metadata service address.
///
/// The classifier covers the entire IPv4 link-local range used by instance,
/// task, and pod metadata services; the AWS `fd00:ec2::/64` service range;
/// Google Compute Engine IPv6; Alibaba ECS IPv4; and Azure's host-local
/// WireServer address. IPv4-mapped and RFC 6052 well-known NAT64 forms receive
/// the same classification. Metadata services can also use private DNS names
/// or provider-specific addresses, so callers must not treat these ranges as
/// provider discovery.
///
/// Known metadata addresses are refused unconditionally by both
/// [`validate_resolved_ips_are_public`] and
/// [`validate_resolved_ips_exclude_metadata`], so an operator opt-in for
/// private destinations never re-opens them.
#[must_use]
pub fn is_cloud_metadata_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            (a == 169 && b == 254) || v4 == ALIBABA_METADATA_V4 || v4 == AZURE_PLATFORM_V4
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[..4] == [0xfd00, 0x0ec2, 0, 0])
                || v6 == GCP_METADATA_V6
                || metadata_embedded_ipv4(v6)
                    .is_some_and(|v4| is_cloud_metadata_ip(std::net::IpAddr::V4(v4)))
        }
    }
}

// ── resolved-address validation ───────────────────────────────────
// These helpers only classify the supplied answer. To prevent DNS rebinding,
// callers must connect to the exact addresses they validated rather than
// resolving the hostname again.

/// Reject a resolution that contains any metadata or non-globally-routable
/// address. This is the default post-resolution SSRF check.
///
/// # DNS pinning
///
/// This function validates only the supplied DNS answer. After it succeeds,
/// the caller must connect to one of these exact validated addresses and must
/// not resolve `host` again; otherwise DNS rebinding can replace the checked
/// destination.
///
/// # Errors
///
/// Returns an error when `ips` is empty, contains a known cloud metadata
/// address, or contains any non-globally-routable address.
pub fn validate_resolved_ips_are_public(
    host: &str,
    ips: &[std::net::IpAddr],
) -> anyhow::Result<()> {
    if ips.is_empty() {
        anyhow::bail!("Failed to resolve host '{host}'");
    }

    for ip in ips {
        if is_cloud_metadata_ip(*ip) {
            anyhow::bail!("Blocked host '{host}' resolved to cloud metadata address {ip}");
        }

        let non_global = match ip {
            std::net::IpAddr::V4(v4) => is_non_global_v4(*v4),
            std::net::IpAddr::V6(v6) => is_non_global_v6(*v6),
        };
        if non_global {
            anyhow::bail!("Blocked host '{host}' resolved to non-global address {ip}");
        }
    }

    Ok(())
}

/// Reject a resolution that contains a known metadata address, but permit
/// other private and loopback addresses. For callers that carry an explicit
/// operator opt-in for private destinations; the known metadata endpoints
/// remain blocked regardless.
///
/// # DNS pinning
///
/// This function validates only the supplied DNS answer. After it succeeds,
/// the caller must connect to one of these exact validated addresses and must
/// not resolve `host` again; otherwise DNS rebinding can replace the checked
/// destination.
///
/// # Errors
///
/// Returns an error when `ips` is empty or contains a known cloud metadata
/// address.
pub fn validate_resolved_ips_exclude_metadata(
    host: &str,
    ips: &[std::net::IpAddr],
) -> anyhow::Result<()> {
    if ips.is_empty() {
        anyhow::bail!("Failed to resolve host '{host}'");
    }

    for ip in ips {
        if is_cloud_metadata_ip(*ip) {
            anyhow::bail!("Blocked host '{host}' resolved to cloud metadata address {ip}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn blocks_rfc1918_and_loopback_and_metadata() {
        for h in [
            "127.0.0.1",
            "localhost",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "[::1]",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private_or_local_host(h), "{h} must be blocked");
        }
    }

    #[test]
    fn allows_public() {
        for h in [
            "1.1.1.1",
            "8.8.8.8",
            "example.com",
            "[2606:4700:4700::1111]",
        ] {
            assert!(!is_private_or_local_host(h), "{h} must be allowed");
        }
    }

    #[test]
    fn ipv4_mapped_v6_follows_v4_classification() {
        assert!(is_non_global_v6(
            "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_non_global_v6(
            "::ffff:1.1.1.1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn ipv4_special_purpose_boundaries_follow_registry() {
        for address in [
            "0.0.0.1",
            "0.255.255.255",
            "100.64.0.1",
            "192.0.0.8",
            "192.0.0.11",
            "192.88.99.1",
            "198.19.255.255",
            "240.0.0.1",
        ] {
            let address = address.parse::<Ipv4Addr>().unwrap();
            assert!(is_non_global_v4(address), "{address} must be blocked");
        }

        for address in [
            "1.0.0.0",
            "100.128.0.0",
            "192.0.0.9",
            "192.0.0.10",
            "192.88.98.255",
            "192.88.100.0",
        ] {
            let address = address.parse::<Ipv4Addr>().unwrap();
            assert!(!is_non_global_v4(address), "{address} must be allowed");
        }

        for address in [
            "198.51.100.0",
            "198.51.100.255",
            "203.0.113.0",
            "203.0.113.255",
        ] {
            let address = address.parse::<Ipv4Addr>().unwrap();
            assert!(is_non_global_v4(address), "{address} must be blocked");
        }

        for address in [
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
        ] {
            let address = address.parse::<Ipv4Addr>().unwrap();
            assert!(!is_non_global_v4(address), "{address} must be allowed");
        }
    }

    #[test]
    fn ipv6_special_purpose_and_reserved_ranges_follow_registry() {
        for address in [
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "4000::1",
            "5f00::1",
            "fec0::1",
        ] {
            let address = address.parse::<Ipv6Addr>().unwrap();
            assert!(is_non_global_v6(address), "{address} must be blocked");
        }

        for address in [
            "64:ff9b::1.1.1.1",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2606:4700:4700::1111",
            "2620:4f:8000::1",
        ] {
            let address = address.parse::<Ipv6Addr>().unwrap();
            assert!(!is_non_global_v6(address), "{address} must be allowed");
        }
    }

    #[test]
    fn cloud_metadata_detection_covers_known_provider_and_embedded_addresses() {
        for address in [
            "169.254.0.0",
            "169.254.169.254",
            "169.254.170.2",
            "169.254.170.23",
            "169.254.255.255",
            "100.100.100.200",
            "168.63.129.16",
            "::ffff:169.254.169.254",
            "::ffff:168.63.129.16",
            "::ffff:100.100.100.200",
            "64:ff9b::169.254.169.254",
            "64:ff9b::168.63.129.16",
            "64:ff9b::100.100.100.200",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "fd00:ec2::",
            "fd00:ec2::23",
            "fd00:ec2::254",
            "fd00:ec2:0:0:ffff:ffff:ffff:ffff",
            "fd20:ce::254",
        ] {
            let address = address.parse().unwrap();
            assert!(
                is_cloud_metadata_ip(address),
                "known metadata endpoint {address} must be blocked"
            );
        }

        for address in [
            "169.253.255.255",
            "169.255.0.0",
            "100.100.100.199",
            "100.100.100.201",
            "168.63.129.15",
            "168.63.129.17",
            "fd00:ec1:ffff:ffff:ffff:ffff:ffff:ffff",
            "fd00:ec2:0:1::",
            "fd20:ce::253",
            "fd20:ce::255",
            "::169.253.169.254",
            "2002:a9fd:a9fe::",
        ] {
            let address = address.parse().unwrap();
            assert!(
                !is_cloud_metadata_ip(address),
                "neighboring non-metadata address {address} must not match"
            );
        }
    }

    #[test]
    fn normalize_domain_strips_scheme_path_and_case() {
        let got = normalize_domain("  HTTPS://Docs.Example.com/path ").unwrap();
        assert_eq!(got, "docs.example.com");
    }

    #[test]
    fn normalize_domain_accepts_ipv4() {
        assert_eq!(normalize_domain("192.168.1.1").unwrap(), "192.168.1.1");
        assert_eq!(normalize_domain("127.0.0.1").unwrap(), "127.0.0.1");
    }

    #[test]
    fn normalize_domain_accepts_ipv6() {
        assert_eq!(normalize_domain("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(normalize_domain("::1").unwrap(), "::1");
        assert_eq!(normalize_domain("[::1]").unwrap(), "::1");
    }

    #[test]
    fn normalize_domain_rejects_unmatched_brackets() {
        assert!(normalize_domain("[::1").is_none());
        assert!(normalize_domain("::1]").is_none());
        assert!(normalize_domain("[127.0.0.1").is_none());
        assert!(normalize_domain("127.0.0.1]").is_none());
    }

    #[test]
    fn normalize_domain_rejects_userinfo() {
        assert!(normalize_domain("https://user@example.com").is_none());
        assert!(normalize_domain("user@example.com").is_none());
        assert!(normalize_domain("https://user:pass@example.com").is_none());
        assert!(normalize_domain("user:pass@example.com").is_none());
    }

    #[test]
    fn normalize_allowed_domains_deduplicates() {
        let got = normalize_allowed_domains(
            vec![
                "example.com".into(),
                "EXAMPLE.COM".into(),
                "https://example.com/".into(),
            ],
            "test",
        )
        .unwrap();
        assert_eq!(got, vec!["example.com".to_string()]);
    }

    #[test]
    fn normalize_allowed_domains_rejects_invalid() {
        let err = normalize_allowed_domains(
            vec!["example.com".into(), "".into(), "   ".into()],
            "test.config",
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid test.config entry"));
    }

    #[test]
    fn host_matches_allowlist_exact() {
        let allowed = vec!["example.com".into()];
        assert!(host_matches_allowlist("example.com", &allowed));
        assert!(!host_matches_allowlist("other.com", &allowed));
    }

    #[test]
    fn host_matches_allowlist_subdomain() {
        let allowed = vec!["example.com".into()];
        assert!(host_matches_allowlist("api.example.com", &allowed));
        assert!(host_matches_allowlist("v2.api.example.com", &allowed));
    }

    #[test]
    fn host_matches_allowlist_wildcard_star() {
        let allowed = vec!["*".into()];
        assert!(host_matches_allowlist("anything.goes.com", &allowed));
        assert!(host_matches_allowlist("192.168.1.1", &allowed));
    }

    #[test]
    fn host_matches_allowlist_wildcard_subdomain() {
        let allowed = vec!["*.example.com".into()];
        assert!(host_matches_allowlist("api.example.com", &allowed));
        assert!(host_matches_allowlist("example.com", &allowed));
        assert!(!host_matches_allowlist("other.com", &allowed));
    }

    #[test]
    fn host_matches_allowlist_ip_exact_only() {
        let allowed = vec!["10.0.0.1".into(), "2001:db8::1".into()];
        assert!(host_matches_allowlist("10.0.0.1", &allowed));
        assert!(!host_matches_allowlist("10.0.0.2", &allowed));
        assert!(host_matches_allowlist("2001:db8::1", &allowed));
        assert!(!host_matches_allowlist("2001:db8::2", &allowed));
    }

    #[test]
    fn is_private_or_local_host_detects_common() {
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("sub.localhost"));
        assert!(is_private_or_local_host("myhost.local"));
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("10.0.0.1"));
        assert!(is_private_or_local_host("192.168.1.1"));
        assert!(is_private_or_local_host("172.16.0.1"));
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("[::1]"));
        assert!(is_private_or_local_host("fe80::1"));
        assert!(is_private_or_local_host("fc00::1"));
    }

    #[test]
    fn is_private_or_local_host_allows_public() {
        assert!(!is_private_or_local_host("example.com"));
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("2001:4860:4860::8888"));
    }

    #[test]
    fn is_private_or_local_host_case_insensitive() {
        assert!(is_private_or_local_host("LOCALHOST"));
        assert!(is_private_or_local_host("Sub.LocalHost"));
        assert!(is_private_or_local_host("Printer.LOCAL"));
    }

    #[test]
    fn blocks_multicast_ipv4() {
        assert!(is_private_or_local_host("224.0.0.1"));
        assert!(is_private_or_local_host("239.255.255.255"));
    }

    #[test]
    fn blocks_broadcast() {
        assert!(is_private_or_local_host("255.255.255.255"));
    }

    #[test]
    fn blocks_unspecified() {
        assert!(is_private_or_local_host("0.0.0.0"));
        assert!(is_private_or_local_host("::"));
    }

    #[test]
    fn blocks_reserved_ipv4() {
        assert!(is_private_or_local_host("240.0.0.1"));
        assert!(is_private_or_local_host("250.1.2.3"));
    }

    #[test]
    fn blocks_documentation_ranges() {
        assert!(is_private_or_local_host("192.0.2.1")); // TEST-NET-1
        assert!(is_private_or_local_host("198.51.100.1")); // TEST-NET-2
        assert!(is_private_or_local_host("203.0.113.1")); // TEST-NET-3
    }

    #[test]
    fn blocks_benchmarking_range() {
        assert!(is_private_or_local_host("198.18.0.1"));
        assert!(is_private_or_local_host("198.19.255.255"));
    }

    #[test]
    fn blocks_rfc6598_shared_address_space() {
        assert!(is_private_or_local_host("100.64.0.1"));
        assert!(is_private_or_local_host("100.127.255.255"));
    }

    #[test]
    fn blocks_ipv6_multicast() {
        assert!(is_private_or_local_host("ff02::1"));
    }

    #[test]
    fn blocks_ipv6_unique_local_fd00() {
        assert!(is_private_or_local_host("fd00::1"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        assert!(is_private_or_local_host("::ffff:127.0.0.1"));
        assert!(is_private_or_local_host("::ffff:192.168.1.1"));
        assert!(is_private_or_local_host("::ffff:10.0.0.1"));
    }

    #[test]
    fn blocks_ipv6_documentation_range() {
        assert!(is_private_or_local_host("2001:db8::1"));
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("93.184.216.34"));
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(!is_private_or_local_host("2607:f8b0:4004:800::200e"));
    }

    #[test]
    fn validate_resolved_ips_blocks_private_resolution() {
        let ips = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))];
        let err = validate_resolved_ips_are_public("example.com", &ips)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("non-global address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_resolved_ips_blocks_all_audited_non_global_classes() {
        for address in [
            "0.0.0.1",
            "192.88.99.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fec0::1",
        ] {
            let ips = [address.parse().unwrap()];
            let err = validate_resolved_ips_are_public("example.test", &ips)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("non-global address"),
                "{address} produced unexpected error: {err}"
            );
        }
    }

    #[test]
    fn validate_resolved_ips_blocks_metadata_even_for_private_opt_in() {
        let ips = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            169, 254, 169, 254,
        ))];
        let err = validate_resolved_ips_exclude_metadata("metadata.test", &ips)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_resolved_ips_blocks_mapped_metadata_even_for_private_opt_in() {
        let ips = ["::ffff:169.254.169.254".parse().unwrap()];
        let err = validate_resolved_ips_exclude_metadata("metadata.test", &ips)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_resolved_ips_blocks_provider_metadata_even_for_private_opt_in() {
        for address in [
            "169.254.170.2",
            "169.254.170.23",
            "100.100.100.200",
            "168.63.129.16",
            "::ffff:100.100.100.200",
            "::ffff:168.63.129.16",
            "64:ff9b::100.100.100.200",
            "64:ff9b::168.63.129.16",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "fd00:ec2::23",
            "fd20:ce::254",
        ] {
            let ips = [address.parse().unwrap()];
            let err = validate_resolved_ips_exclude_metadata("metadata.test", &ips)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("cloud metadata address"),
                "{address} produced unexpected error: {err}"
            );
        }
    }

    #[test]
    fn validate_resolved_ips_blocks_ec2_ipv6_metadata_even_for_private_opt_in() {
        let ips = ["fd00:ec2::254".parse().unwrap()];
        let err = validate_resolved_ips_exclude_metadata("metadata.test", &ips)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_resolved_ips_metadata_is_not_reported_as_generic_private() {
        let ips = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            169, 254, 169, 254,
        ))];
        let err = validate_resolved_ips_are_public("metadata.test", &ips)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cgnat_and_reserved_v4_blocked() {
        assert!(is_non_global_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_non_global_v4(Ipv4Addr::new(240, 0, 0, 1)));
    }
}
