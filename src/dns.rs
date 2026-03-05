use anyhow::Result;
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;

use crate::output;

/// AD-specific SRV record queries to enumerate
const SRV_QUERIES: &[(&str, &str)] = &[
    ("_ldap._tcp.dc._msdcs", "Domain Controllers"),
    ("_kerberos._tcp", "Kerberos KDC"),
    ("_gc._tcp", "Global Catalog"),
    ("_kpasswd._tcp", "Kerberos Password Change"),
    ("_ldap._tcp.pdc._msdcs", "Primary Domain Controller"),
    ("_ldap._tcp.gc._msdcs", "Global Catalog (MSDCS)"),
];

/// Run DNS-based AD enumeration
pub async fn run(target: &str) -> Result<Option<String>> {
    output::section("DNS ENUMERATION");

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    output::info(&format!("Attempting domain discovery from {}", target));
    let domain = discover_domain_from_target(target).await;
    if let Some(ref d) = domain {
        output::success(&format!("Domain: {}", d));
    } else {
        output::warning("Reverse DNS lookup failed");
    }

    // If we don't have a domain, we can't do SRV enumeration
    let domain = match domain {
        Some(d) => d,
        None => {
            output::warning("Could not determine domain name from DNS");
            output::info("Try providing the domain with: ./aydee <ip> -d <domain>");
            return Ok(None);
        }
    };

    // Enumerate SRV records
    output::info(&format!("Enumerating SRV records for {}", domain));
    println!();

    for (srv, description) in SRV_QUERIES {
        let query = format!("{}.{}.", srv, domain);
        match resolver.srv_lookup(query.clone()).await {
            Ok(lookup) => {
                output::success(description);
                for record in lookup.iter() {
                    output::kv(
                        "Host",
                        &format!(
                            "{} (port: {}, priority: {}, weight: {})",
                            record.target().to_string().trim_end_matches('.'),
                            record.port(),
                            record.priority(),
                            record.weight()
                        ),
                    );
                }
            }
            Err(_) => {
                output::fail(&format!("{} — no records", description));
            }
        }
    }

    println!();
    check_open_recursion(target).await;

    Ok(Some(domain))
}

/// Discover a likely AD domain from an IP/FQDN target.
/// For IP targets, this performs reverse DNS and strips the host label.
/// For FQDN targets, this strips the first label directly.
pub async fn discover_domain_from_target(target: &str) -> Option<String> {
    if let Some(domain) = domain_from_hostname(target) {
        return Some(domain);
    }

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let addr = target.parse::<std::net::IpAddr>().ok()?;
    let lookup = resolver.reverse_lookup(addr).await.ok()?;
    let hostname = lookup.iter().next()?.to_string();

    domain_from_hostname(hostname.trim_end_matches('.'))
}

/// Convert an FQDN like dc01.corp.local to corp.local.
pub fn domain_from_hostname(hostname: &str) -> Option<String> {
    let parts: Vec<&str> = hostname.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        Some(parts[1..].join("."))
    } else {
        None
    }
}

async fn check_open_recursion(target: &str) {
    let Ok(ip) = target.parse::<std::net::IpAddr>() else {
        return;
    };

    let ns_group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], ns_group),
        ResolverOpts::default(),
    );

    output::info("Testing DNS recursion behavior (unauthenticated query)...");
    match resolver.lookup_ip("www.microsoft.com.").await {
        Ok(ips) if ips.iter().next().is_some() => {
            output::warning(
                "Potential open recursion: target DNS resolved external name for unauthenticated query",
            );
            output::info("Verify recursion ACL policy before treating this as exposure");
        }
        _ => {
            output::success("No obvious open-recursion response for external lookup");
        }
    }
}
