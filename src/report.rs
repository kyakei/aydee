use anyhow::Result;
use serde::Serialize;
use std::fs;

use crate::auth_recon::AuthFinding;

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub target: String,
    pub domain: Option<String>,
    pub usernames_collected: Vec<String>,
    pub authenticated_findings: Vec<AuthFinding>,
}

pub fn write_json(path: &str, report: &RunReport) -> Result<()> {
    let data = serde_json::to_string_pretty(report)?;
    fs::write(path, data)?;
    Ok(())
}
