use anyhow::Result;
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::output;

/// Run extra unauthenticated AD attack-surface checks.
/// Current checks focus on AD CS Web Enrollment / NTLM relay surface.
pub async fn run(target: &str, open_ports: &[u16]) -> Result<()> {
    let web_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 80 | 8080))
        .collect();
    let tls_web_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 443 | 8443))
        .collect();

    if web_ports.is_empty() && tls_web_ports.is_empty() {
        return Ok(());
    }

    output::section("UNAUTH ATTACK SURFACE");
    output::info("Checking for AD CS Web Enrollment exposure and NTLM relay surface");

    for port in web_ports {
        check_adcs_web_enrollment(target, "http", port).await;
    }

    for port in tls_web_ports {
        check_adcs_web_enrollment(target, "https", port).await;
    }

    Ok(())
}

#[derive(Debug)]
struct HttpProbeResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: String,
}

async fn check_adcs_web_enrollment(target: &str, scheme: &str, port: u16) {
    let candidates = ["/certsrv/", "/certsrv/certfnsh.asp", "/certsrv/certnew.cer"];
    let mut seen_adcs = false;
    let mut ntlm_auth = false;
    let mut anon_ok = false;

    for path in candidates {
        let response = if scheme.eq_ignore_ascii_case("https") {
            https_get(target, port, path).await
        } else {
            http_get(target, port, path).await
        };

        let Ok(resp) = response else {
            continue;
        };

        let status = resp.status_code;
        let offers_ntlm = resp.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("www-authenticate")
                && (v.to_ascii_lowercase().contains("ntlm")
                    || v.to_ascii_lowercase().contains("negotiate"))
        });

        let likely_adcs_path = path.starts_with("/certsrv/");
        let likely_adcs_body = resp.body.to_ascii_lowercase().contains("certsrv");
        if likely_adcs_path && (status == 200 || status == 401 || likely_adcs_body) {
            seen_adcs = true;
        }

        if status == 401 && offers_ntlm {
            ntlm_auth = true;
        }
        if status == 200 {
            anon_ok = true;
        }
    }

    if seen_adcs {
        output::warning(&format!(
            "Potential AD CS Web Enrollment detected on {}://{}:{}",
            scheme, target, port
        ));
        if ntlm_auth {
            output::warning(
                "NTLM/Negotiate auth offered on /certsrv — relay-to-ADCS (ESC8) may be possible",
            );
        }
        if anon_ok {
            output::warning("At least one /certsrv endpoint responded anonymously (HTTP 200)");
        }
        output::info("Hardening: disable Web Enrollment if unused, enforce EPA/HTTPS, and block NTLM relay paths");
    } else {
        output::info(&format!(
            "No obvious AD CS Web Enrollment endpoints found on {}://{}:{}",
            scheme, target, port
        ));
    }
}

async fn https_get(target: &str, port: u16, path: &str) -> Result<HttpProbeResponse> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("https://{}:{}{}", target, port, path);
    let response = client
        .get(url)
        .header("User-Agent", "aydee/0.1")
        .send()
        .await?;

    let status_code = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = response.text().await.unwrap_or_default();

    Ok(HttpProbeResponse {
        status_code,
        headers,
        body,
    })
}

async fn http_get(target: &str, port: u16, path: &str) -> Result<HttpProbeResponse> {
    let raw = http_get_raw(target, port, path).await?;
    Ok(HttpProbeResponse {
        status_code: parse_status_code(&raw).unwrap_or(0),
        headers: extract_headers(&raw),
        body: raw,
    })
}

async fn http_get_raw(target: &str, port: u16, path: &str) -> Result<String> {
    let addr = format!("{}:{}", target, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await??;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aydee/0.1\r\nConnection: close\r\n\r\n",
        path, target
    );
    timeout(Duration::from_secs(3), stream.write_all(req.as_bytes())).await??;

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        anyhow::bail!("empty HTTP response");
    }

    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

fn parse_status_code(resp: &str) -> Option<u16> {
    let first = resp.lines().next()?;
    let mut parts = first.split_whitespace();
    let _http = parts.next()?;
    parts.next()?.parse().ok()
}

fn extract_headers(resp: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in resp.lines().skip(1) {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    headers
}
