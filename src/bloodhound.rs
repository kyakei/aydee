use anyhow::Result;
use std::io::ErrorKind;
use tokio::process::Command;

use crate::output;

/// Run BloodHound collection using available auth methods.
pub async fn run_collection(
    target: &str,
    domain: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
    collection: &str,
) -> Result<bool> {
    let output_dir = "bloodhound_output";
    let mut attempted = false;
    let mut any_success = false;
    let mut installed = false;

    output::section("BLOODHOUND COLLECTION");
    output::info(&format!(
        "Attempting BloodHound collection with --collection {} --zip",
        collection
    ));

    if let Some(pass) = password {
        attempted = true;
        let (ok, found_binary) =
            run_password(target, domain, username, pass, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if let Some(hash) = ntlm_hash {
        attempted = true;
        let (ok, found_binary) =
            run_ntlm(target, domain, username, hash, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if kerberos {
        attempted = true;
        let (ok, found_binary) =
            run_kerberos(target, domain, username, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if !attempted {
        output::warning("No BloodHound auth method provided (--password, --ntlm, or --kerberos)");
        return Ok(false);
    } else if !installed {
        output::warning("No BloodHound collector binary found (tried: bloodhound-python, bloodhound-ce-python)");
        return Ok(false);
    } else if any_success {
        output::success(&format!(
            "BloodHound collection completed. Zip output should be in ./{}/",
            output_dir
        ));
        return Ok(true);
    } else {
        output::warning("BloodHound methods were attempted, but no collection succeeded");
        return Ok(false);
    }
}

async fn run_password(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: password");
    run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("-p", password)],
        &[],
    )
    .await
}

async fn run_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm_hash: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: NTLM hash");
    let hashes = if ntlm_hash.contains(':') {
        ntlm_hash.to_string()
    } else {
        format!("aad3b435b51404eeaad3b435b51404ee:{}", ntlm_hash)
    };
    run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("--hashes", &hashes)],
        &[],
    )
    .await
}

async fn run_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: Kerberos (-k)");
    run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[],
        &["-k"],
    )
    .await
}

fn base_cmd(
    bin: &str,
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg("-u")
        .arg(username)
        .arg("-d")
        .arg(domain)
        .arg("-ns")
        .arg(target)
        .arg("-c")
        .arg(collection)
        .arg("--zip")
        .arg("-o")
        .arg(output_dir);
    cmd
}

async fn run_with_candidates(
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
    kv_args: &[(&str, &str)],
    flag_args: &[&str],
) -> Result<(bool, bool)> {
    let bins = ["bloodhound-python", "bloodhound-ce-python"];
    let mut found_any = false;

    for bin in bins {
        let mut cmd = base_cmd(bin, target, domain, username, collection, output_dir);
        for (k, v) in kv_args {
            cmd.arg(k).arg(v);
        }
        for f in flag_args {
            cmd.arg(f);
        }

        match cmd.output().await {
            Ok(out) => {
                found_any = true;
                if out.status.success() {
                    output::success(&format!("{} method succeeded", bin));
                    return Ok((true, true));
                }

                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                output::warning(&format!("{} method failed (exit {:?})", bin, out.status.code()));
                if !stderr.trim().is_empty() {
                    output::kv("stderr", stderr.trim());
                } else if !stdout.trim().is_empty() {
                    output::kv("stdout", stdout.trim());
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                continue;
            }
            Err(e) => {
                output::warning(&format!("Could not run {} ({})", bin, e));
                found_any = true;
            }
        }
    }

    Ok((false, found_any))
}
