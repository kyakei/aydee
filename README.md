# AyDee

AyDee is an operator-focused Active Directory reconnaissance and attack-surface automation tool. It is built to cover the common first-pass AD workflow from one CLI and write the output into one results directory instead of making you glue together a dozen separate commands.

AyDee is organized around the normal early AD workflow:

1. Discover and fingerprint the target
2. Validate access and enumerate LDAP, SMB, and WinRM
3. Surface attack paths, roast material, and BloodHound data
4. Write reports and artifacts into a single workspace

## What AyDee Is Good At

- Fast first-pass AD triage from a host or domain controller target
- Password, NTLM, and Kerberos-backed recon from the same CLI
- Domain discovery from target identity, DNS, and LDAP
- LDAP fingerprinting, anonymous bind checks, and authenticated directory recon
- SMB share enumeration, SYSVOL inspection, and GPP hunting
- WinRM credential validation
- BloodHound collection with operator-friendly prompts
- Credential attack helpers for Kerberoast, AS-REP roast, and pre2k/default machine-account checks
- Multi-format reporting with JSON, text, HTML, and a workspace manifest

## What It Is Not

- Not a full exploitation framework
- Not stealth-first in `auto` mode
- Not fully self-contained: several modules shell out to external tools

## Installation

### Release Binaries

Prebuilt binaries are published on GitHub Releases:

- `aydee-v<version>-linux-x86_64`
- `aydee-v<version>-windows-x86_64.exe`

### Build From Source

Requirements:

- Rust toolchain with `cargo`

```bash
cargo build --release
./target/release/aydee --help
```

### Runtime Dependencies

AyDee skips unsupported feature paths when the needed tool is missing, instead of aborting the whole run.

Core operator tools:

- `smbclient`
- `nxc`, `netexec`, or `crackmapexec`
- `dig`
- `ntpdate` or `rdate`

BloodHound:

- `bloodhound-python` or `bloodhound-ce-python`

Impacket helpers:

- `impacket-GetUserSPNs` or `GetUserSPNs.py`
- `impacket-GetNPUsers` or `GetNPUsers.py`
- `impacket-getTGT` or `getTGT.py`

Note:

- The Windows binary is published and supported by the release workflow, but the full feature set is still easiest to use on Linux because most external operator tooling is Linux-first.

## Quick Start

### Anonymous Fingerprinting

```bash
./aydee --target 10.10.10.100
```

### Password-Backed Recon

```bash
./aydee --target 10.10.10.100 -u alice -p 'Password123!'
```

### NTLM-Backed Recon

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice \
  -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff
```

### Kerberos-Backed Recon

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice -k --ccache ./alice.ccache
```

### BloodHound Only

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice -p 'Password123!' \
  --only bloodhound
```

### Focused LDAP + SMB Checks By Tag

```bash
./aydee --target 10.10.10.100 -u alice -p 'Password123!' \
  --only ldap-auth,smb-auth \
  --tags adcs,delegation,gpp
```

### Explicit Spray Run

```bash
./aydee --target 10.10.10.100 -d corp.local \
  --mode manual --only spray \
  --spray-passwords 'Winter2025!' \
  --userlist ./users.txt
```

## Auth Modes

- Anonymous: omit credentials; authenticated stages are skipped.
- Password: `-u` plus `-p`
- NTLM: `-u` plus `-H`
- Kerberos: `-u` plus `-k`, optionally with `--ccache`

Important behavior:

- A ccache alone does not enable Kerberos-backed collectors. Use `-k`.
- If `KRB5CCNAME` is already exported, AyDee will detect and use it.
- If credentials are incomplete, authenticated modules are skipped instead of partially running.

## Run Modes

| Mode | Behavior |
| --- | --- |
| `auto` | Default. Runs the main non-invasive pipeline. |
| `semi` | Conservative. Skips noisier stages like `kerberos`, `spray`, `credential`, and `bloodhound` unless explicitly selected. |
| `manual` | Runs only modules named in `--only`. |

## Modules

Available values for `--only`:

- `scan`
- `dns`
- `ldap`
- `ldap-auth`
- `smb-auth`
- `rpc`
- `winrm`
- `kerberos`
- `spray`
- `credential`
- `bloodhound`
- `attacks`

Compatibility aliases:

- `auth-ldap` -> `ldap-auth`
- `credential-attacks` -> `credential`

## Tag Filters

`--tags` currently narrows deeper authenticated LDAP and SMB subchecks.

LDAP tags:

- `kerberoast`
- `asreproast`
- `delegation`
- `maq`
- `trusts`
- `adcs`
- `computers`
- `pso`
- `dcsync`
- `laps`
- `gpo`
- `shadow-creds`
- `user-desc`

SMB tags:

- `gpp`
- `sysvol`

## Core Options

- `--target <TARGET>` target IP or hostname
- `-d, --domain <DOMAIN>` domain hint
- `-u, --username <USERNAME>` username
- `-p, --password <PASSWORD>` password
- `-H, --ntlm <NTLM>` NTLM hash
- `-k, --kerberos` enable Kerberos auth mode
- `--ccache <CCACHE>` set or resolve `KRB5CCNAME`
- `--collection <COLLECTION>` BloodHound collection scope
- `-m, --mode <MODE>` `auto`, `semi`, or `manual`
- `--only <MODULES>` comma-separated module allowlist
- `--tags <TAGS>` comma-separated subcheck filter
- `-P, --ports <PORTS>` custom port list or range
- `--timeout <SECONDS>` TCP scan timeout
- `--ldap-port <PORT>` LDAP port override
- `-w, --wordlist <WORDLIST>` Kerberos user-enum wordlist
- `--spray-passwords <LIST>` comma-separated spray passwords
- `--userlist <PATH>` external spray user list
- `--spray-limit <N>` max users per spray round
- `--spray-delay <MS>` delay between spray attempts
- `--no-fix-clock-skew` disable startup clock skew correction
- `--non-interactive` suppress all prompts
- `-o, --output <DIR>` custom output directory
- `--report-json <PATH>` JSON report path
- `--report-text <PATH>` text summary path
- `--manifest-json <PATH>` workspace manifest path

Backward-compatible aliases also exist for older flags such as `--auth-user`, `--auth-pass`, `--auth-ntlm`, `--spray-password`, `--spray-userlist`, `--spray-max-users`, and `--spray-delay-ms`.

## What Gets Written

By default, each run writes to:

```text
results/<target>_<unix_timestamp>/
```

Typical artifacts:

- `aydee_report.json`
- `aydee_summary.txt`
- `aydee_report.html`
- `workspace_manifest.json`
- `bloodhound_output/`
- `kerberoast_hashes_*.txt`
- `asreproast_hashes_*.txt`
- recovered `.ccache` tickets from successful pre2k/default machine-account hits

The report set gives you:

- structured JSON for scripting or ingestion
- a plain text summary for quick review
- an HTML report with findings and risk scoring
- a workspace manifest of generated artifacts

## Operator Notes

- `manual` mode requires `--only`.
- `--non-interactive` suppresses prompt-driven stages such as clock sync and BloodHound confirmation.
- Clock skew correction is attempted at startup unless `--no-fix-clock-skew` is set.
- Missing external tools do not stop the whole run; AyDee skips only the affected path.
- Password spraying is opt-in only.
- The `attacks` stage focuses on unauthenticated attack-surface checks such as AD CS Web Enrollment, coercion endpoints, and relay-adjacent surfaces.

## Legal

Use AyDee only on systems you own or are explicitly authorized to assess.
