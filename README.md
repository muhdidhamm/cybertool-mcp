# Unified ThreatLens MCP Server

A comprehensive MCP (Model Context Protocol) server that gives Claude Desktop access to **279+ Unified ThreatLens Linux security tools** running inside a Docker container. Ask Claude to perform penetration testing, vulnerability scanning, network reconnaissance, PQC readiness checks, and disk incident response workflows — all through natural language.

## Architecture

```
Claude Desktop  ──stdio──►  Docker Container (unified-threatlens-server)
                                │
                                ├── MCP Server (FastMCP / Python)
                                │       │
                                │       ├── Recon (nmap, masscan, zmap, hping3, ...)
                                │       ├── Web Security (nikto, sqlmap, ffuf, nuclei, ...)
                                │       ├── Brute-Force (hydra, john, hashcat, patator, ...)
                                │       ├── OSINT (theHarvester, amass, sherlock, shodan, ...)
                                │       ├── Exploitation (metasploit, searchsploit, SET, ...)
                                │       ├── Active Directory (crackmapexec, impacket, bloodhound, ...)
                                │       ├── Wireless (aircrack-ng, wifite, reaver, kismet, ...)
                                │       ├── Sniffing/Spoofing (bettercap, ettercap, mitm6, ...)
                                │       ├── Network (tcpdump, tshark, socat, iperf3, ...)
                                │       ├── Forensics & RE (binwalk, sleuthkit, volatility3, radare2, ...)
                                │       ├── Vuln Scanning (wpscan, lynis, chkrootkit, clamav, ...)
                                │       ├── Database (odat, sqlninja, oscanner, ...)
                                │       ├── VoIP (sipvicious, sipp, enumiax, ...)
                                │       ├── Crypto/Encoding (hash-id, base64, hex, ...)
                                │       └── Utilities (shell, curl, file mgmt, ...)
                                │
                                └── Cyber Operations Linux Rolling Distro (full toolset + metapackages)
```

## Prerequisites

- **Docker Desktop** installed and running
- **Claude Desktop** (latest version)
- ~15-25 GB disk space for the container image (includes metapackages)

## Quick Start

### 1. Build the Docker Image

**Windows (PowerShell):**
```powershell
cd d:\projects\MCP\unified-threatlens
.\build.ps1
```

**Linux / macOS:**
```bash
cd /path/to/unified-threatlens
chmod +x build.sh
./build.sh
```

**Or manually:**
```bash
docker build -t git.abyres.net/mcp/unified-threatlens-server:latest .
```

> The first build takes **20-40 minutes** as it installs all metapackages and security tools. Subsequent builds use Docker cache.

### 2. Configure Claude Desktop

Open your Claude Desktop config file:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add or merge this configuration:

```json
{
  "mcpServers": {
    "unified-threatlens": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--cap-add", "NET_RAW",
        "--cap-add", "NET_ADMIN",
        "-v", "unified-threatlens-output:/opt/uts-mcp/output",
        "-v", "unified-threatlens-data:/opt/uts-mcp/data",
        "-v", "unified-threatlens-reports:/opt/uts-mcp/reports",
        "-v", "unified-threatlens-logs:/opt/uts-mcp/logs",
        "git.abyres.net/mcp/unified-threatlens-server:latest"
      ],
      "env": {
        "AUTO_UPDATE": "first"
      }
    }
  }
}
```

For streamable HTTP mode in Claude Desktop, use a single bridge entry and pin `mcp-remote`:

```json
{
  "mcpServers": {
    "unified-threatlens": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote@0.1.38",
        "http://localhost:8080/mcp"
      ]
    }
  }
}
```

Node.js LTS is recommended for bridge stability (Node 20+).

Before using this config, create persistent Docker volumes:

```bash
docker volume create unified-threatlens-output
docker volume create unified-threatlens-logs
docker volume create unified-threatlens-data
docker volume create unified-threatlens-reports
```

### 3. Restart Claude Desktop

Completely quit and relaunch Claude Desktop. The **unified-threatlens** tools should appear in the tools menu (hammer icon).

## Incident Response Cheatsheet

Use this quick map for Linux disk-full incidents.

| Scenario | Start With | Outcome |
|---|---|---|
| Production server suddenly 96-100% full | `remote_linux_disk_triage` | Finds likely root cause: full mounts, inode pressure, large files, deleted-open files, Docker/log growth |
| Need a change-safe plan before touching system | `remote_linux_disk_remediate_plan` | Returns prioritized remediation steps and suggested commands (no remote changes) |
| Need emergency space recovery (approved window) | `remote_linux_disk_cleanup` | Performs conservative cleanup; requires explicit `confirm=true` |
| Need forensic evidence from remote host | `remote_disk_image_create` | Creates disk image with hash artifacts (`dc3dd` or `ddrescue`) |
| Source disk detached and attached to analysis host | `attached_disk_rootcause_analysis` | Detects device/partitions, mounts read-only, and analyzes what consumed space |
| Need to bootstrap SSH key auth quickly | `ssh_keygen_for_remote_setup` | Generates reusable keypair and returns copy/paste remote setup steps |
| Need to validate remote auth before incident tools | `remote_ssh_preflight` | Confirms SSH key login + optional passwordless sudo readiness |

**Safety notes**
- Attached-disk analysis includes a guard to avoid mounting the active OS root disk.
- Read-only mount options are used where possible (`ro`, `noload`, `norecovery`).
- Always pass the real remote host/IP; avoid `localhost` unless intentionally analyzing the same machine.

**Streamlined SSH onboarding (one-time)**
1. Run `ssh_keygen_for_remote_setup` to create a persistent keypair in `/opt/uts-mcp/data/ssh-keys`.
2. Install the returned public key in remote `~/.ssh/authorized_keys`.
3. Run `remote_ssh_preflight` to validate key auth and sudo readiness.
4. Set `REMOTE_SSH_KEY_PATH` to avoid passing `ssh_key_path` in every call.

## Audit Logging (AI + MCP Tool Activity)

Unified ThreatLens can persist structured audit logs for:
- MCP tool invocations (tool name + arguments)
- MCP tool results/errors
- Underlying command executions (`run_command`) and outputs

Audit logs are written as JSONL to:
- `/opt/uts-mcp/logs/mcp_audit.jsonl`

### Session grouping (important)

Audit events are normalized with explicit identity fields:
- `mcp_session_id`: MCP execution session id for tool/audit correlation
- `chat_session_id`: client chat id used for saved conversation turns
- `main_session_id`: top-level explicit session anchor used by dashboard aggregation
- `invocation_id`: per-tool invocation trace id

To ensure **one user request = one session** and complete capture, recommended flow is:
1. `start_session(chat_session_id=...)`
2. Run required tools
3. `end_session(session_id=..., chat_session_id=..., user_message=..., assistant_message=..., tool_calls_json=..., report_paths_json=..., metadata_json=..., turn_id=...)`

Compatibility:
- `save_chat_exchange(...)` is still fully supported and can be used as a standalone tool.
- If `end_session` is called without both `user_message` and `assistant_message`, session finalization still runs and response includes a warning that inline chat capture was skipped.

If you don't call `start_session`, the server will generate an `auto-*` session id on first tool use and reuse it until another session is started.

Environment variables:
- `MCP_AUDIT_LOG_ENABLED` (default: `true`) — set to `false` to disable
- `MCP_AUDIT_LOG_PATH` (default: `/opt/uts-mcp/logs/mcp_audit.jsonl`) — custom file path
- `MCP_AUDIT_MAX_FIELD_CHARS` (default: `4000`) — truncation limit for large fields
- `TIMEZONE` (default: `Asia/Kuala_Lumpur`) — primary timezone for displayed/generated date-time values
- `TZ` (fallback) — secondary timezone source when `TIMEZONE` is not set

Notes:
- Sensitive-looking fields (password/token/auth/key/cookie) are redacted.
- Chat-level natural language messages are only logged when they appear in tool arguments from the client flow.
- Use `audit_log_guery` to filter/search the JSONL audit events (or `audit_log_query` alias).
- Use `audit_log_export_csv` to export filtered audit events for SIEM or incident response workflows.
- Use `audit_log_stats` to get summary metrics (top tools, failure rate, top errors, optional time buckets).
- Use `save_report_artifact` if report text/HTML was generated ad-hoc and you need it saved into `/opt/uts-mcp/reports` for dashboard visibility.
- `end_session` now performs report finalization using chat `report_paths` plus recent output-directory report files (`.html/.pdf/.docx`) and returns `finalize_summary`.
- `finalize_summary.resolved` records `resolved_by` provenance for each copied source path.
- Dashboard session report links now include only server-accessible files that actually exist.
- For binary artifacts (especially DOCX), prefer `save_binary_report_artifact` over text `write_file` workflows.

## Web Dashboard (Sessions, Logs, Reports)

Unified ThreatLens includes an optional web dashboard that visualizes:
- Scan AI sessions (derived from `session_id` when provided, otherwise time-window grouped)
- Full MCP tool execution timeline and results per session
- Linked generated reports and output files
- Playbook management (create, update, clone, validate, run-history)

Enable with environment variables:
- `MCP_DASHBOARD_ENABLED=true`
- `MCP_DASHBOARD_BACKEND=fastapi` (recommended; `legacy` remains available)
- `MCP_DASHBOARD_HOST=0.0.0.0`
- `MCP_DASHBOARD_PORT=8090`
- `MCP_PLAYBOOKS_DIR=/opt/uts-mcp/data/playbooks` (persistent YAML playbook store)
- `MCP_SUBSCRIPTION_LICENSE_PATH=/opt/uts-mcp/data/subscription.lic`
- `MCP_SUBSCRIPTION_TRUST_MODE=prod` (`prod` ignores key overrides; `dev` can allow them)
- `MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE=false` (must be `true` with `dev` mode to use override key vars)
- `MCP_SUBSCRIPTION_KEYRING_PATH=/opt/uts-mcp/config/subscription-keys/keys.json` (pinned issuer keyring in image)
- `MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=true` (temporary migration compatibility)
- `MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS=14`
- `MCP_DASHBOARD_AUTH_TOKEN=<strong-random-token>` (optional but recommended)
- `MCP_DASHBOARD_USERNAME=<dashboard-user>` (optional login mode)
- `MCP_DASHBOARD_PASSWORD=<dashboard-password>` (optional login mode)
- `MCP_DASHBOARD_PASSWORD_HASH=pbkdf2_sha256$<iterations>$<salt>$<hex_digest>` (preferred over plain password)
- `MCP_DASHBOARD_LOGIN_MAX_ATTEMPTS=5`
- `MCP_DASHBOARD_LOGIN_WINDOW_SECONDS=300`
- `MCP_DASHBOARD_LOGIN_LOCKOUT_SECONDS=900`
- `MCP_DASHBOARD_COOKIE_SECURE=true` (recommended when served over HTTPS)
- `TIMEZONE=Asia/Kuala_Lumpur` (timezone display/source of truth)
- `TZ=Asia/Kuala_Lumpur` (fallback and OS-level timezone hint)

Timezone precedence for the server is: `TIMEZONE` -> `TZ` -> `Asia/Kuala_Lumpur`.

Docker Compose defaults in this repo expose:
- `http://localhost:8090` for `unified-threatlens-stream`
- `http://localhost:8091` for `unified-threatlens-dashboard`

When `MCP_DASHBOARD_AUTH_TOKEN` is set, pass it as:
- Header: `Authorization: Bearer <token>`
- Or URL query (browser convenience): `http://localhost:8091/?token=<token>`

When username/password are configured, a login page is enabled at `/login`.
After sign-in, users are redirected to the dashboard index page with menus for:
- Session timeline
- Reports
- Output files
- Playbooks
- Logout

`MCP_DASHBOARD_PASSWORD_HASH` uses this format:
- `pbkdf2_sha256$<iterations>$<salt>$<hex_digest>`

If both `MCP_DASHBOARD_PASSWORD` and `MCP_DASHBOARD_PASSWORD_HASH` are set, the hash value is used.

Generate a hash with:

```bash
python3 scripts/generate_dashboard_password_hash.py
python3 scripts/generate_dashboard_password_hash.py --password "ChangeMe!" --iterations 200000
```

Generate a complete dashboard env file with secure defaults:

```bash
python3 scripts/generate_dashboard_env.py
python3 scripts/generate_dashboard_env.py --username secops --output .env.dashboard --overwrite
```

Use it with Docker Compose:

```bash
docker compose --env-file .env.dashboard up -d unified-threatlens
```

### Subscription Control

Unified ThreatLens supports signed subscription enforcement for MCP tool execution.

- Dashboard features (login, sessions, reports, output files) remain available even when subscription is missing or expired.
- MCP tool calls are blocked when subscription is missing, invalid, not started, or expired.
- Production trust is pinned to image-shipped keyring material by default (`MCP_SUBSCRIPTION_TRUST_MODE=prod`).
- Blocked calls return a structured result payload with:
  - `success: false`
  - `code: subscription_*`
  - `error` and `subscription` details

Generate a signed `subscription.lic` using a private key:

```bash
python3 scripts/generate_subscription_license.py \
  --subscriber-name "Acme Corp" \
  --start-date "2026-04-01" \
  --end-date "2026-12-31" \
  --issuer-id "unified-threatlens" \
  --key-id "vendor-default-2026" \
  --private-key /path/to/subscription-private.pem \
  --output /tmp/subscription.lic
```

Verify license content/signature before upload:

```bash
python3 scripts/verify_subscription_license.py \
  --license-path /tmp/subscription.lic
```

#### Creating a real vendor keypair (production runbook)

Use this once per issuer key rotation cycle.

1. Generate the signing private key on an offline/restricted machine:

```bash
mkdir -p secure-subscription-keygen
cd secure-subscription-keygen
umask 077
openssl genpkey -algorithm Ed25519 -out vendor-subscription-private.pem
```

2. Derive the public key:

```bash
openssl pkey -in vendor-subscription-private.pem -pubout -out vendor-subscription-public.pem
```

3. Compute SHA-256 SPKI fingerprint (base64) for key pinning:

```bash
PUBKEY_FINGERPRINT=$(openssl pkey -pubin -in vendor-subscription-public.pem -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)
echo "$PUBKEY_FINGERPRINT"
```

4. Add/update pinned key files in the repository image content:
   - Place public key at `config/subscription-keys/<your-key-id>.pem`
   - Add entry in `config/subscription-keys/keys.json`:
     - `issuer_id`
     - `key_id`
     - `public_key_path`
     - `fingerprint_sha256` (from step 3)

5. Build and deploy a new image release so runtime trust anchor is updated.

6. Issue licenses using matching `issuer_id` and `key_id`:

```bash
python3 scripts/generate_subscription_license.py \
  --subscriber-name "Acme Corp" \
  --start-date "2026-04-01" \
  --end-date "2026-12-31" \
  --issuer-id "your-issuer-id" \
  --key-id "your-key-id" \
  --private-key /secure/path/vendor-subscription-private.pem \
  --output /tmp/subscription.lic
```

#### Keeping vendor keys safe

- Never store `vendor-subscription-private.pem` in this repo, Docker image, container volume, or CI logs.
- Keep the private key offline or in HSM/KMS; restrict signing access to a small release/security group.
- Enforce `chmod 600` and encrypted-at-rest storage for private key backups.
- Rotate keys via release process only (new key in `keys.json` + image deployment), then retire old key ids.
- Keep production in pinned mode:
  - `MCP_SUBSCRIPTION_TRUST_MODE=prod`
  - `MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE=false`
- Use dev overrides only for controlled local testing; never in production.

Development-only key override verification (never use in production):

```bash
python3 scripts/verify_subscription_license.py \
  --license-path /tmp/subscription.lic \
  --trust-mode dev \
  --allow-key-override \
  --public-key-path /path/to/dev-subscription-public.pem
```

Upload `subscription.lic` in the dashboard **Subscription** tab, or via API:

```bash
curl -X POST "http://localhost:8090/api/subscription/upload?token=<token>" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Subscription-Filename: subscription.lic" \
  --data-binary @subscription.lic
```

Subscription upload endpoint accepts any filename ending in `.lic`, and always stores it as the configured subscription path (default: `/opt/uts-mcp/data/subscription.lic`). It cannot modify pinned trust-anchor keys.

### Subscription Trust Migration

Phase A (compatibility release):
- Keep `MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=true`.
- Accept old licenses without `issuer_id`/`key_id` when exactly one pinned key exists.
- Emit migration guidance in operator docs/logs.

Phase B (enforcement release):
- Set `MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=false`.
- Require `issuer_id` and `key_id` in all licenses.
- Rotate/introduce issuer keys via app image release only.

### Lightweight Dashboard Test Profile

For fast dashboard development without building the full tool image, use the `dash-test` profile.  
It uses a slim Python image, bind-mounts the local source tree, and reuses the same persistent Docker volumes.

```bash
# build and start lightweight dashboard test container
docker compose --profile dash-test up -d unified-threatlens-dashboard-test

# open dashboard
# http://localhost:8092

# stop test container
docker compose --profile dash-test stop unified-threatlens-dashboard-test

# remove test container
docker compose --profile dash-test rm -sf unified-threatlens-dashboard-test
```

Default test audit log path:
- `/opt/uts-mcp/logs/mcp_audit.jsonl`

Dashboard API endpoints:
- `GET /api/sessions`
- `GET /api/sessions/<session_id>`
- `GET /api/reports`
- `GET /api/output-files`
- `GET /api/file?path=<absolute_path>`
- `GET /api/playbooks`
- `GET /api/playbooks/<name>`
- `POST /api/playbooks`
- `PUT /api/playbooks/<name>`
- `DELETE /api/playbooks/<name>`
- `POST /api/playbooks/<name>/clone`
- `POST /api/playbooks/<name>/validate`
- `GET /api/playbooks/<name>/runs?limit=50`

Notes:
- Playbook execution is intentionally AI-chat driven via MCP tool `run_playbook(...)`.
- Dashboard/API run route is disabled to avoid mismatched execution context.
- Example:
  - `run_playbook(name="recon_external", target="192.168.0.36", variables_json="{}")`

Playbook persistence behavior:
- Playbooks are stored as YAML under `/opt/uts-mcp/data/playbooks` by default.
- `MCP_PLAYBOOKS_DIR` overrides that location.
- A default `recon_external.yaml` is seeded automatically on first run.
- Delete operations are soft-delete by default (moved to `.trash/` under playbook store).

Dashboard startup troubleshooting:
- Legacy dashboard mode now fails fast if required static assets are missing:
  - `tools/dashboard_assets/index.html`
  - `tools/dashboard_assets/dashboard.css`
  - `tools/dashboard_assets/dashboard.js`
- On failure, an audit event `dashboard.assets.missing` is written with missing filenames and asset directory path.
- Recovery checklist:
  - Ensure those files exist in your checkout/image.
  - If using Docker, rebuild image after pulling latest changes: `docker compose build`.
  - For quick local validation, run the dashboard test profile and open `http://localhost:8092`.
  - Optionally switch to FastAPI backend via `MCP_DASHBOARD_BACKEND=fastapi`.

Report/session linking behavior:
- Reports created via `create_report`, `create_report_from_tool_outputs`, or `save_report_artifact` are linked to the originating session.
- Dashboard also backfills links by report file timestamp proximity to session timeline when explicit linkage is missing.

## Available Tools (279+)

The sections below are a representative catalog of key tools and workflows.  
The MCP server exposes many additional tools beyond this summary, including specialized wrappers and reporting pipelines.

To verify the exact current count from source code:

```bash
python3 scripts/tool_count.py
python3 scripts/tool_count.py --breakdown
python3 scripts/tool_count.py --json
```

### Network Scanning & Recon (representative)
| Tool | Description |
|---|---|
| `nmap_scan` | Full-featured Nmap scanning with NSE scripts |
| `masscan_scan` | Ultra-fast port scanning |
| `zmap_scan` | Internet-wide single-port scanning |
| `arp_scan` | Local network ARP host discovery |
| `traceroute_host` | Route tracing |
| `mtr_trace` | Combined traceroute + ping path analysis |
| `ping_host` | ICMP ping check |
| `hping3_probe` | Advanced TCP/UDP/ICMP packet crafting |
| `tcp_connect_test` | TCP port connectivity test |
| `nbtscan_host` | NetBIOS enumeration |
| `unicornscan_scan` | Asynchronous stateless TCP/UDP scanner |
| `netdiscover_scan` | ARP-based network discovery |

### Web Application Security (representative)
| Tool | Description |
|---|---|
| `nikto_scan` | Web server vulnerability scanner |
| `dirb_scan` | Directory brute-forcing |
| `gobuster_dir` | Fast directory/file enumeration |
| `ffuf_fuzz` | Fast web fuzzer with FUZZ placeholder |
| `feroxbuster_scan` | Recursive content discovery (Rust-based) |
| `sqlmap_scan` | SQL injection detection & exploitation |
| `commix_scan` | Command injection testing |
| `xsser_scan` | XSS vulnerability detection |
| `joomscan_scan` | Joomla CMS scanner |
| `droopescan_scan` | Multi-CMS vulnerability scanner |
| `wapiti_scan` | Web application vulnerability scanner |
| `whatweb_scan` | Web technology fingerprinting |
| `wafw00f_detect` | WAF detection |
| `sslscan_check` | SSL/TLS analysis |
| `sslyze_check` | Deep SSL/TLS analysis |
| `testssl_check` | Comprehensive SSL/TLS testing |
| `wfuzz_scan` | Web application fuzzing |
| `nuclei_scan` | Template-based vulnerability scanner |

### Password & Brute-Force (representative)
| Tool | Description |
|---|---|
| `hydra_attack` | Network service brute-forcing |
| `john_crack` | Password hash cracking (John the Ripper) |
| `john_show` | Show cracked passwords |
| `hashcat_crack` | Hash cracking (CPU mode) |
| `medusa_attack` | Parallel brute-force |
| `ncrack_attack` | High-speed network auth cracker |
| `patator_attack` | Multi-purpose brute-forcer |
| `crowbar_attack` | SSH key / RDP / VNC brute-force |
| `brutespray_attack` | Auto-brute services from Nmap output |
| `cewl_generate` | Custom wordlist from website |
| `crunch_generate` | Pattern-based wordlist generation |
| `cupp_generate` | Targeted password profiling |

### OSINT & Information Gathering (representative)
| Tool | Description |
|---|---|
| `theharvester_search` | Email/subdomain/host harvesting |
| `fierce_scan` | DNS recon for non-contiguous IPs |
| `dnsenum_scan` | DNS enumeration |
| `dnsrecon_scan` | DNS reconnaissance |
| `dnsmap_scan` | Subdomain brute-force |
| `dnstwist_scan` | Typosquat/lookalike domain detection |
| `amass_enum` | Subdomain enumeration |
| `sublist3r_enum` | Fast subdomain discovery |
| `subfinder_enum` | Passive subdomain discovery |
| `assetfinder_enum` | Related domain/subdomain finder |
| `httpx_probe` | HTTP server probing |
| `naabu_portscan` | Fast port scanner (ProjectDiscovery) |
| `dmitry_scan` | Multi-purpose info gathering |
| `whois_lookup` | WHOIS queries |
| `dig_lookup` | DNS record lookup |
| `enum4linux_scan` | Windows/Samba enumeration |
| `sherlock_search` | Social media account hunting |
| `spiderfoot_scan` | OSINT automation |
| `snmpwalk_scan` | SNMP enumeration |
| `onesixtyone_scan` | SNMP community string scanner |
| `shodan_search` | Shodan device search |
| `shodan_host` | Shodan IP information |

### Active Directory & Windows (representative)
| Tool | Description |
|---|---|
| `crackmapexec_scan` | Swiss army knife for AD pentesting |
| `impacket_secretsdump` | Dump SAM/LSA/NTDS secrets |
| `impacket_psexec` | Remote command execution (PsExec) |
| `impacket_smbclient` | SMB share enumeration |
| `impacket_wmiexec` | Remote execution via WMI |
| `impacket_getnpusers` | AS-REP roasting |
| `impacket_getuserspns` | Kerberoasting |
| `smbclient_list` | List SMB shares |
| `responder_listen` | LLMNR/NBT-NS hash capture |
| `kerbrute_userenum` | AD username enumeration |
| `kerbrute_passwordspray` | Password spraying via Kerberos |
| `ldapdomaindump_dump` | LDAP domain information dump |
| `bloodhound_collect` | AD data collection for BloodHound |

### Exploitation (representative)
| Tool | Description |
|---|---|
| `searchsploit` | Exploit-DB search |
| `searchsploit_examine` | View exploit source code |
| `searchsploit_mirror` | Copy exploit to output |
| `msfconsole_run` | Run Metasploit commands |
| `msfvenom_generate` | Payload generation |
| `msf_db_nmap` | Nmap via Metasploit DB |
| `nmap_vuln_scan` | Nmap vulnerability scripts |
| `setoolkit_run` | Social-Engineer Toolkit |
| `gophish_list_campaigns` | GoPhish campaign management |

### Wireless Security (representative)
| Tool | Description |
|---|---|
| `airmon_start` / `airmon_stop` | Monitor mode control |
| `airodump_scan` | Wireless AP scanning |
| `aireplay_deauth` | Deauthentication frames |
| `aircrack_crack` | WPA/WPA2 handshake cracking |
| `wifite_attack` | Automated wireless auditing |
| `reaver_attack` | WPS brute-force (Pixie Dust) |
| `kismet_scan` | Wireless network detector |
| `macchanger_change` / `macchanger_show` | MAC address manipulation |
| `hcxdumptool_capture` | PMKID/handshake capture |
| `hcxpcapngtool_convert` | Convert captures for hashcat |
| `cowpatty_crack` | Offline WPA dictionary attack |
| `wavemon_info` | Wireless signal info |

### Sniffing & Spoofing (representative)
| Tool | Description |
|---|---|
| `bettercap_run` | Network attack framework |
| `ettercap_scan` | MITM attacks |
| `dsniff_sniff` | Password sniffing |
| `arpspoof_attack` | ARP spoofing |
| `mitm6_attack` | IPv6-based MITM |
| `p0f_fingerprint` | Passive OS fingerprinting |

### Network Analysis (representative)
| Tool | Description |
|---|---|
| `tcpdump_capture` | Packet capture |
| `tcpdump_read` | Read pcap files |
| `tshark_analyze` | Wireshark CLI analysis |
| `socat_relay` | Port forwarding |
| `proxychains_run` | Proxy-tunneled commands |
| `iperf3_test` | Network bandwidth testing |
| `ssldump_capture` | SSL/TLS traffic decoding |

### Forensics & Reverse Engineering (representative)
| Tool | Description |
|---|---|
| `binwalk_analyze` | Binary file analysis |
| `foremost_recover` | File carving/recovery |
| `scalpel_carve` | Fast file carving |
| `sleuthkit_fls` / `sleuthkit_icat` / `sleuthkit_mmls` / `sleuthkit_fsstat` | Disk image forensics |
| `steghide_extract` / `steghide_info` | Steganography extraction |
| `outguess_extract` | OutGuess steganography |
| `stegcracker_crack` | Brute-force stego passphrases |
| `exiftool_extract` | Metadata extraction |
| `strings_extract` | String extraction from binaries |
| `file_identify` | File type identification |
| `xxd_hexdump` | Hex dump display |
| `pdfcrack_crack` | PDF password cracking |
| `fcrackzip_crack` | ZIP password cracking |
| `rarcrack_crack` | RAR/7z password cracking |
| `volatility3_run` | Memory dump analysis |
| `yara_scan` | Malware signature scanning |
| `bulk_extractor_run` | Bulk data extraction |
| `radare2_analyze` | Binary reverse engineering |
| `rizin_analyze` | Rizin binary analysis |
| `gdb_analyze` | GDB debugging commands |
| `objdump_disassemble` | Binary disassembly |
| `strace_trace` | System call tracing |
| `ltrace_trace` | Library call tracing |
| `apktool_decode` | Android APK decoding |
| `dex2jar_convert` | DEX to JAR conversion |
| `upx_unpack` | UPX binary unpacking |

### Vulnerability Scanning (representative)
| Tool | Description |
|---|---|
| `wpscan` | WordPress vulnerability scanning |
| `lynis_audit` | System security audit |
| `chkrootkit_scan` | Rootkit detection |
| `rkhunter_scan` | Rootkit/backdoor scanner |
| `clamav_scan` | Malware scanning |
| `nmap_script_scan` | NSE script-based scanning |

### Database Assessment (representative)
| Tool | Description |
|---|---|
| `sqlninja_attack` | MSSQL injection exploitation |
| `bbqsql_scan` | Blind SQL injection |
| `odat_scan` | Oracle DB attacking tool |
| `oscanner_scan` | Oracle installation scanner |
| `sidguesser_scan` | Oracle SID guessing |
| `tnscmd_probe` | Oracle TNS listener probing |
| `dbpwaudit_scan` | Database password auditing |

### VoIP Security (representative)
| Tool | Description |
|---|---|
| `svmap_scan` | SIP device scanning |
| `svwar_enumerate` | SIP extension enumeration |
| `svcrack_crack` | SIP password cracking |
| `enumiax_scan` | IAX2 username enumeration |
| `inviteflood_attack` | SIP INVITE flood testing |
| `sipp_test` | SIP performance testing |
| `rtpbreak_analyze` | RTP stream detection |
| `sctpscan_scan` | SCTP port scanning |

### Cryptography & Encoding (representative)
| Tool | Description |
|---|---|
| `hash_identify` | Hash type identification |
| `generate_hash` | Hash generation (MD5, SHA, etc.) |
| `base64_encode` / `base64_decode` | Base64 encoding/decoding |
| `url_encode` / `url_decode` | URL encoding/decoding |
| `hex_encode` / `hex_decode` | Hex encoding/decoding |

### Utilities (representative)
| Tool | Description |
|---|---|
| `shell_exec` | Execute arbitrary commands |
| `curl_request` | HTTP requests |
| `download_file` | File downloads |
| `ipcalc` | IP/CIDR calculation |
| `list_wordlists` | Browse available wordlists |
| `list_output_files` | View saved results |
| `read_output_file` | Read result files |
| `write_file` | Save data to files |
| `system_info` | Container system information |

### SSL/TLS & HTTPS Security (representative)
| Tool | Description |
|---|---|
| `ssl_cert_info` | Retrieve certificate details via OpenSSL |
| `ssl_cert_chain` | Display full certificate chain |
| `ssl_cipher_enum` | Enumerate supported ciphers/protocols |
| `ssl_vuln_scan` | Check Heartbleed/POODLE/ROBOT/CCS-related issues |
| `sslyze_full` | Deep SSL/TLS analysis with SSLyze |
| `testssl_full` | Comprehensive TLS posture check with testssl.sh |
| `ssl_hsts_check` | Verify HSTS behavior |
| `ssl_security_headers` | Check HTTPS security headers |

### Post-Quantum Cryptography (PQC) (representative)
| Tool | Description |
|---|---|
| `pqc_full_assessment` | Scored PQC readiness report (0-100) |
| `pqc_kex_probe` | Probe Kyber/ML-KEM hybrid key exchange support |
| `pqc_cert_check` | Analyze cert signature quantum-vulnerability |
| `pqc_tls13_groups` | Inspect TLS 1.3 negotiated groups for PQC indicators |
| `testssl_pqc` | testssl.sh scan with PQC-focused filtering |
| `sslyze_pqc` | SSLyze scan with PQC-focused filtering |
| `pqc_quantum_risk_summary` | Fast quantum risk level + migration checklist |

### Burp Suite & Web Pipelines (representative)
| Tool | Description |
|---|---|
| `burp_crawl_and_audit` | Automated Burp crawl + audit flow |
| `burp_passive_crawl` | Passive crawl and discovery mode |
| `burp_check_vulns` | Targeted SQLi/XSS/RCE/SSRF checks |
| `burp_sitemap_crawl` | Endpoint/sitemap discovery |
| `burp_scan_with_report` | Multi-tool web assessment with report generation |

### Stress / DoS Simulation (representative)
| Tool | Description |
|---|---|
| `slowhttptest_attack` | Slow HTTP DoS simulation |
| `siege_test` | HTTP load/stress testing |
| `goldeneye_test` | HTTP DoS testing utility |
| `t50_flood` | Packet flood simulation |
| `dhcpig_exhaust` | DHCP starvation simulation |
| `thc_ssl_dos` | SSL/TLS DoS simulation |

### Reporting (representative)
| Tool | Description |
|---|---|
| `create_report` | Generate professional report (HTML/PDF/Markdown/JSON/CSV) |
| `list_reports` | List generated report files |
| `read_report` | Read report contents |
| `delete_report` | Remove outdated reports |

### Disk Incident Response (remote/offline) (representative)
| Tool | Description |
|---|---|
| `ssh_keygen_for_remote_setup` | Generate reusable SSH keypair for remote MCP workflows |
| `remote_ssh_preflight` | Validate key auth and sudo readiness before running remote actions |
| `remote_linux_disk_triage` | Remote SSH triage for sudden disk-full incidents |
| `remote_linux_disk_remediate_plan` | Safe remediation plan without changes |
| `remote_linux_disk_cleanup` | Controlled cleanup (requires confirm=true) |
| `remote_disk_image_create` | Remote forensic imaging via dc3dd/ddrescue |
| `attached_disk_rootcause_analysis` | Read-only attached-disk root-cause analysis |
| `attached_disk_compromise_investigation` | Offline compromise investigation (SSH success, persistence, IOCs) + report |

## Metapackages Installed

The container installs these metapackages (robust installer skips any unavailable):

- `kali-tools-top10` — The 10 most popular tools
- `kali-tools-information-gathering` — OSINT & recon
- `kali-tools-vulnerability` — Vulnerability scanners
- `kali-tools-web` — Web application tools
- `kali-tools-database` — Database assessment
- `kali-tools-passwords` — Password tools
- `kali-tools-wireless` — Wireless auditing
- `kali-tools-reverse-engineering` — RE tools
- `kali-tools-exploitation` — Exploit frameworks
- `kali-tools-social-engineering` — Social engineering
- `kali-tools-sniffing-spoofing` — Network sniffing/spoofing
- `kali-tools-post-exploitation` — Post-exploitation
- `kali-tools-forensics` — Digital forensics
- `kali-tools-crypto-stego` — Crypto & steganography
- `kali-tools-reporting` — Reporting tools
- `kali-tools-rfid` — RFID tools
- `kali-tools-sdr` — Software defined radio
- `kali-tools-voip` — VoIP security

## Python Security Packages

Pre-installed Python libraries for scripting:

`scapy`, `requests`, `beautifulsoup4`, `paramiko`, `pycryptodome`, `cryptography`,
`pyopenssl`, `impacket`, `ldap3`, `python-nmap`, `shodan`, `pwntools`, `ropper`,
`capstone`, `keystone-engine`, `yara-python`

## Example Conversations

**Network recon:**
> "Scan 192.168.1.0/24 with nmap to find all live hosts and open ports with service versions"

**Web app testing:**
> "Use ffuf to fuzz directories on http://target.local, then run nuclei for known vulnerabilities"

**Active Directory:**
> "Use crackmapexec to enumerate SMB shares on 10.0.0.5, then try AS-REP roasting with impacket"

**Wireless:**
> "Start monitor mode on wlan0, scan for nearby access points, then capture a WPA handshake"

**Forensics:**
> "Analyze this memory dump with volatility3 to list processes and extract password hashes"

**Password cracking:**
> "Identify the hash type of '5f4dcc3b5aa765d61d8327deb882cf99' and crack it with john using rockyou"

**Post-Quantum TLS:**
> "Run a full post-quantum cryptography readiness assessment on api.company.com and summarize migration steps"

**Disk incident response (remote):**
> "Triage why disk is 98% full on 10.10.20.15 over SSH, then generate a remediation plan without making changes"

**Attached disk analysis (offline):**
> "Analyze attached disk /dev/sda on remote host 10.10.30.9, mount read-only, and identify what caused space exhaustion"

## HTTP Transport Mode (Optional)

For remote access or multi-client setups, run with HTTP transport:

```bash
docker compose --profile http up -d unified-threatlens-stream
```

This exposes the MCP server on port 8080 with streamable-http transport at:

`http://localhost:8080/mcp`

## Transport Choice: stdio vs streamable-http

Use this quick guide to choose the right MCP transport:

| Transport | Best For | How It Runs | Claude Config |
|---|---|---|---|
| `stdio` | Default local desktop usage | Claude starts container per session via `docker run -i` | `command` + `args` |
| `streamable-http` | Remote access, multi-client, always-on server | Run `unified-threatlens-stream` service with Docker Compose | `npx mcp-remote@0.1.38 http://localhost:8080/mcp` |

### Recommended Default

- Use `stdio` for most single-user local setups (simplest and isolated).
- Use `streamable-http` when you need a persistent endpoint or shared access.

### Quick Start Commands

```bash
# stdio mode (Claude launches container itself)
# no separate server process required

# streamable-http mode (run persistent MCP HTTP endpoint)
docker compose --profile http up -d unified-threatlens-stream
```

## Security Notice

This toolkit is designed for **authorized security testing only**. Always ensure you have explicit written permission before testing any systems. Unauthorized access to computer systems is illegal. The tools in this container are powerful and should be used responsibly.

## Troubleshooting

**Claude Desktop doesn't show unified-threatlens tools:**
1. Verify Docker Desktop is running
2. Check the image exists: `docker images unified-threatlens-server`
3. Test manually: `docker run -i --rm git.abyres.net/mcp/unified-threatlens-server:latest`
4. Check Claude Desktop logs at `%APPDATA%\Claude\logs\` (Windows)

**Claude error: `Tool result could not be submitted`**
1. Confirm Claude config has only one active Unified ThreatLens entry and, for stream mode, uses `mcp-remote@0.1.38`.
2. Verify stream service status: `docker ps --filter "name=unified-threatlens-stream"` and check `docker logs --tail 50 unified-threatlens-stream`.
3. Run `mcp_health_check(nonce="diag-1")` followed by `start_session(...)`.
4. Check audit evidence quickly:
   - `docker exec unified-threatlens-stream python -c "from pathlib import Path; p=Path('/opt/uts-mcp/logs/mcp_audit.jsonl'); print(p.exists(), p.stat().st_size if p.exists() else 0)"`
   - If matching `tool.result` events exist for the failing time window, treat this as bridge/client lifecycle interruption and retry.
5. End each completed run with `end_session(session_id=..., chat_session_id=...)` so report finalization runs and only accessible report links appear in dashboard.
6. For DOCX/PDF/HTML generated outside MCP report tools, upload with `save_binary_report_artifact(...)` instead of text-only `write_file`.
7. Restart Claude Desktop after config changes.

**Build fails:**
- Ensure Docker Desktop has at least 8 GB memory allocated
- Check internet connectivity (the build downloads packages from main repos)
- Try building without cache: `docker build --no-cache -t git.abyres.net/mcp/unified-threatlens-server:latest .`
- The robust installer skips unavailable packages — some tools may not be in current repos

**Tool times out:**
- Increase the `timeout` parameter in the tool call
- Some tools (masscan, hashcat, amass) need longer timeouts for large scans

## License

MIT
