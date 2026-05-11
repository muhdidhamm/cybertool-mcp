# Unified ThreatLens MCP Server — Usage Guide

This guide shows you how to use Claude Desktop to run every security tool available in your Unified ThreatLens MCP server. Just type natural language prompts — Claude will pick the right tool automatically.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Network Scanning & Recon](#1-network-scanning--recon)
3. [Web Application Testing](#2-web-application-testing)
4. [SSL/TLS & HTTPS Security](#3-ssltls--https-security)
5. [Password Cracking & Brute-Force](#4-password-cracking--brute-force)
6. [OSINT & Information Gathering](#5-osint--information-gathering)
7. [Active Directory & Windows](#6-active-directory--windows)
8. [Exploitation](#7-exploitation)
9. [Wireless & WiFi Cracking](#8-wireless--wifi-cracking)
10. [Sniffing & Spoofing](#9-sniffing--spoofing)
11. [Network Analysis](#10-network-analysis)
12. [Forensics & Steganography](#11-forensics--steganography)
13. [Reverse Engineering](#12-reverse-engineering)
14. [Vulnerability Scanning](#13-vulnerability-scanning)
15. [Database Assessment](#14-database-assessment)
16. [VoIP Security](#15-voip-security)
17. [Cryptography & Encoding](#16-cryptography--encoding)
18. [Generating Reports](#17-generating-reports)
19. [Utilities & General Commands](#18-utilities--general-commands)
20. [Database & Pattern Updates](#19-database--pattern-updates)
21. [Post-Quantum Cryptography (PQC) Assessment](#20-post-quantum-cryptography-pqc-assessment)
22. [Disk Incident Response (Remote & Attached Disk)](#21-disk-incident-response-remote--attached-disk)
23. [Chaining Tools Together](#22-chaining-tools-together)
24. [Tips & Best Practices](#23-tips--best-practices)
25. [Dashboard Playbook Management](#24-dashboard-playbook-management)
26. [Subscription Trust Hardening](#25-subscription-trust-hardening)

---

## Disk Incident Quick Playbook

Use this table when disk usage suddenly spikes and you need the fastest path to the right tool.

| Symptom / Scenario | Run This MCP Tool First | What It Gives You |
|---|---|---|
| Linux server suddenly at 96-100% disk | `remote_linux_disk_triage` | Fast root-cause clues: full mounts, inode pressure, top growth paths, deleted-open files, Docker/log hotspots |
| Need to bootstrap SSH key auth quickly | `ssh_keygen_for_remote_setup` | Generates reusable keypair and returns remote install steps |
| Need to verify key auth/sudo before remote actions | `remote_ssh_preflight` | Validates SSH connectivity and passwordless sudo readiness |
| Need a safe action plan before making changes | `remote_linux_disk_remediate_plan` | Prioritized remediation steps and exact commands (no host changes) |
| Need to reclaim space now (approved change window) | `remote_linux_disk_cleanup` | Controlled cleanup workflow; requires explicit `confirm=true` |
| Need forensic-grade image of a remote disk | `remote_disk_image_create` | `dc3dd`/`ddrescue` imaging plus hash artifacts for evidence integrity |
| Source server disk removed and attached to analysis host | `attached_disk_rootcause_analysis` | Device/partition detection, read-only mounts, and offline root-cause analysis |
| Unsure if `/dev/sda` is the attached source disk | `attached_disk_rootcause_analysis` (with explicit `device`) | Built-in guard against analyzing the current OS root disk |
| Suspect logs are filling storage | `remote_linux_disk_triage` | `journalctl` and `/var/log` growth evidence |
| Suspect hidden usage from deleted files | `remote_linux_disk_triage` | `lsof +L1` evidence of deleted-but-open file handles |
| Suspect Docker/container growth | `remote_linux_disk_triage` | `docker system df` and `/var/lib/docker` usage hotspots |
| Need defensible offline analysis with minimal risk | `attached_disk_rootcause_analysis` | Read-only mount options (`ro`, `noload`, `norecovery`) and evidence output |

---

## Getting Started

### 1. Create Docker Volumes

Before building or running the container, create the persistent volumes. These store scan output, logs, reports, and tool databases so they survive container restarts.

```bash
docker volume create cybertool-mcp-output
docker volume create cybertool-mcp-logs
docker volume create cybertool-mcp-data
docker volume create cybertool-mcp-reports
```

### 2. Build the Docker Image

First build (pulls all packages — takes a while):

```bash
docker compose build
```

Subsequent builds after code changes are fast because the Dockerfile uses a multi-stage build. The heavy tool layer is cached and only the MCP server code is rebuilt:

```bash
docker compose build
```

To force a full rebuild (e.g., after adding new packages to the Dockerfile):

```bash
docker compose build --no-cache
```

### 3. Configure Claude Desktop

Copy the contents of `claude_desktop_config.json` into your Claude Desktop configuration file. See README.md for the exact file location on your OS.

### Transport Choice: `stdio` vs `streamable-http`

Use this quick guide to pick the right MCP transport mode:

| Transport | Best For | How It Runs | Claude Desktop Config |
|---|---|---|---|
| `stdio` | Default local desktop usage | Claude starts a container on demand using `docker run -i` | `command` + `args` |
| `streamable-http` | Persistent endpoint, remote/multi-client access | Run the `cybertool-mcp-stream` Docker Compose service | `command: npx`, `args: [\"-y\", \"mcp-remote@0.1.38\", \"http://localhost:8080/mcp\"]` |

Recommended:
- Use `stdio` for most single-user local workflows.
- Use `streamable-http` when you need a long-running shared MCP endpoint.
- Use Node.js LTS (Node 20+) for stable `mcp-remote` behavior.

Start HTTP transport service:

```bash
docker compose --profile http up -d cybertool-mcp-stream
```

### 4. Start Using

Open a new conversation in Claude Desktop. You should see the **cybertool-mcp** tools listed under the hammer icon.

You don't need to remember tool names. Just describe what you want in plain English and Claude will select the appropriate tool(s).

> **Important:** Always ensure you have written authorization before testing any system you don't own.

### Timezone configuration

Unified ThreatLens uses these timezone settings for displayed/generated date-time values:
- `TIMEZONE` (primary)
- `TZ` (fallback)
- default: `Asia/Kuala_Lumpur`

Precedence is: `TIMEZONE` -> `TZ` -> `Asia/Kuala_Lumpur`.

### Session grouping (recommended)

For clean audit logs and dashboard timelines, use this pattern for each user request:
- Call `start_session(chat_session_id=...)` at the beginning of the turn
- Run the required security tools
- Call `end_session(session_id=..., chat_session_id=..., user_message=..., assistant_message=..., tool_calls_json=..., report_paths_json=..., metadata_json=..., turn_id=...)` to persist chat + finalize report archival under `/opt/uts-mcp/reports/<session_id>/<timestamp>/`

Notes:
- Audit payloads include normalized identity fields (`mcp_session_id`, `chat_session_id`, `main_session_id`, `invocation_id`) for stable correlation.
- Recommended capture path is now 3 steps (`start_session` -> tools -> `end_session` inline chat payload).
- `save_chat_exchange(...)` remains supported for backward compatibility.
- If `end_session` is called without both `user_message` and `assistant_message`, it still succeeds, finalizes reports, and returns warnings indicating inline chat capture was skipped.
- Dashboard session report list now shows only report files that are accessible on the MCP server.
- If you generated DOCX/PDF/HTML outside MCP report generators, persist them with `save_binary_report_artifact(...)`.

### Claude bridge submission error runbook

If Claude shows `Tool result could not be submitted`, use this quick flow:

1. Confirm only one active Unified ThreatLens MCP entry exists in `claude_desktop_config.json`.
2. For `streamable-http`, pin bridge args to `mcp-remote@0.1.38` and use Node.js LTS.
3. Check stream container health:
   - `docker ps --filter "name=cybertool-mcp-stream"`
   - `docker logs --tail 50 cybertool-mcp-stream`
4. Run `mcp_health_check(nonce="diag-1")`, then `start_session(...)`.
5. Verify `/opt/uts-mcp/logs/mcp_audit.jsonl` contains matching `tool.invoke`/`tool.result` (same `invocation_id`) for the same time window.
6. Run `end_session(session_id=..., chat_session_id=...)` so the server finalizes chat-linked reports into the session report path.
7. If `tool.result` exists while Claude still errors, treat it as bridge/client lifecycle interruption and retry once after Claude restart.

### Subscription trust hardening

Subscription verification uses image-pinned trust keys by default.

- `MCP_SUBSCRIPTION_TRUST_MODE=prod` keeps verification pinned to in-image keyring.
- `MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE=false` prevents runtime public-key override in production.
- `MCP_SUBSCRIPTION_KEYRING_PATH=/opt/uts-mcp/config/subscription-keys/keys.json` defines trusted `issuer_id`/`key_id`.
- `MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=true` allows temporary compatibility for old licenses during migration.

License payloads should include:
- `subscriber_name`
- `subscription_start_date`
- `subscription_end_date`
- `issued_at`
- `issuer_id`
- `key_id`

Development-only override testing:

```bash
python3 scripts/verify_subscription_license.py \
  --license-path /tmp/subscription.lic \
  --trust-mode dev \
  --allow-key-override \
  --public-key-path /path/to/dev-subscription-public.pem
```

Production recommendation:
- Keep override disabled and rotate issuer keys only through signed application image releases.

### Dashboard startup troubleshooting

If dashboard startup fails in `legacy` backend mode, verify required static assets exist:

- `tools/dashboard_assets/index.html`
- `tools/dashboard_assets/dashboard.css`
- `tools/dashboard_assets/dashboard.js`

Behavior:
- Startup now fails fast when required assets are missing.
- An audit event `dashboard.assets.missing` is emitted with missing filenames and asset directory path.

Recovery:
- Pull latest code and rebuild image: `docker compose build`
- Validate quickly with dashboard test profile: `docker compose --profile dash-test up -d cybertool-mcp-dashboard-test`
- Open `http://localhost:8092` to confirm UI assets load
- Optional fallback: set `MCP_DASHBOARD_BACKEND=fastapi`

---

## 1. Network Scanning & Recon

### Port Scanning

```
Scan 192.168.1.1 for open ports and identify running services
```

```
Do a full TCP SYN scan on 10.0.0.0/24 for ports 1-1000
```

```
Run a fast masscan on 192.168.1.0/24 to find all open ports at 5000 packets/sec
```

```
Scan port 22, 80, 443, 8080 on target.example.com with OS detection enabled
```

### Host Discovery

```
Find all live hosts on my local network using ARP scan
```

```
Ping sweep 10.10.10.0/24 to see which hosts are up
```

```
Run netdiscover in passive mode on eth0 to see what's on the network
```

### Route & Connectivity

```
Trace the route to google.com and show each hop
```

```
Run MTR to 8.8.8.8 with 20 pings per hop to analyze the network path
```

```
Test if port 3389 is open on 10.0.0.5 using TCP connect
```

### Advanced Probing

```
Send SYN packets to port 80 on 192.168.1.1 using hping3
```

```
Run a ZMap scan for port 443 across the 10.0.0.0/16 range at 2000 pps
```

```
Scan 192.168.1.0/24 for NetBIOS names and information
```

---

## 2. Web Application Testing

### Directory & File Discovery

```
Brute-force directories on https://target.com using gobuster with the common wordlist
```

```
Run ffuf against https://target.com/FUZZ to find hidden directories, filter out 404s
```

```
Use feroxbuster to recursively discover content on https://target.com with depth 3
```

```
Run dirb against http://192.168.1.100 looking for php and html files
```

### Vulnerability Scanning

```
Scan https://target.com with nikto for web server vulnerabilities
```

```
Run nuclei against https://target.com checking for critical and high severity issues
```

```
Use wapiti to scan https://target.com for SQL injection, XSS, and command injection
```

### SQL Injection

```
Test https://target.com/page?id=1 for SQL injection with sqlmap at level 3, risk 2
```

```
Run sqlmap on https://target.com/login with POST data "username=admin&password=test"
```

### Command Injection & XSS

```
Test https://target.com/ping?host=127.0.0.1 for command injection using commix
```

```
Scan https://target.com/search?q=test for XSS vulnerabilities using xsser
```

### CMS Scanning

```
Scan https://blog.target.com for WordPress vulnerabilities, enumerate plugins and users
```

```
Check if https://shop.target.com is running Joomla and scan for vulnerabilities
```

```
Scan https://cms.target.com with droopescan for Drupal vulnerabilities
```

### Technology Fingerprinting

```
Identify what technologies and frameworks https://target.com is using with whatweb
```

```
Check if https://target.com is behind a web application firewall
```

### Burp Suite — Automated Web App Assessment

The `burp_scan_with_report` tool runs a full automated pipeline: crawl, vulnerability scan, and professional report generation — all in one command.

**Full automated scan with report:**

```
Run a full Burp Suite security assessment on https://target.com and generate an HTML report
```

```
Do a quick Burp scan of https://staging.target.com and give me a PDF report
```

**Targeted vulnerability checks:**

```
Check https://target.com/search?q=test for SQL injection, XSS, SSRF, and command injection
```

```
Run targeted vulnerability checks on https://target.com/api/v1/users?id=1 — focus on SQLi and RCE
```

**Crawl and discover sitemap:**

```
Crawl https://target.com to discover all endpoints, directories, and technologies
```

```
Map out the full sitemap of https://app.target.com using Burp's sitemap crawler
```

**Direct Burp crawl and audit:**

```
Run a Burp Suite crawl-and-audit scan against https://target.com
```

**Workflow: scan then report:**

```
First, run a full Burp security assessment on https://target.com.
Then generate a detailed PDF report with all findings, severity ratings, and remediation advice.
```

---

## 3. SSL/TLS & HTTPS Security

### Certificate Inspection

```
Show me the SSL certificate details for github.com
```

```
Check when the SSL certificate for example.com expires
```

```
Display the full certificate chain for mysite.com
```

### Vulnerability Checks

```
Check if target.com is vulnerable to Heartbleed
```

```
Run a full SSL vulnerability scan on target.com port 443 — check for Heartbleed,
POODLE, CCS injection, DROWN, and ROBOT
```

```
Test which TLS protocol versions target.com supports (SSL3, TLS 1.0, 1.1, 1.2, 1.3)
```

### Cipher & Configuration Analysis

```
Enumerate all supported SSL/TLS ciphers on target.com
```

```
Run a comprehensive sslscan on target.com:443
```

```
Do a full testssl.sh assessment of https://target.com
```

```
Use sslyze to check target.com for Heartbleed, CCS injection, and ROBOT
```

### Security Headers

```
Check HTTP security headers on https://target.com — HSTS, CSP, X-Frame-Options
```

```
Is HSTS enabled on target.com?
```

### Mail/Service SSL

```
Check the SSL certificate on mail.target.com SMTP port 587 using STARTTLS
```

```
Test SSL on the IMAP server at mail.target.com port 993
```

---

## 4. Password Cracking & Brute-Force

### Online Brute-Force

```
Brute-force SSH login on 10.0.0.5 with username admin using rockyou.txt
```

```
Run hydra against ftp://10.0.0.5 trying usernames from /opt/uts-mcp/output/users.txt
```

```
Use medusa to brute-force RDP on 10.0.0.10 with user administrator
```

```
Try password spraying against 10.0.0.5 SSH with a list of 5 common passwords
```

### Offline Hash Cracking

```
Identify what type of hash this is: 5f4dcc3b5aa765d61d8327deb882cf99
```

```
Crack the hashes in /opt/uts-mcp/output/hashes.txt using john with rockyou
```

```
Use hashcat in mode 1000 (NTLM) to crack /opt/uts-mcp/output/ntlm_hashes.txt
```

```
Show me the passwords john has already cracked from hashes.txt
```

### Wordlist Generation

```
Generate a custom wordlist by spidering https://target.com with CeWL
```

```
Create a wordlist of all 4-digit numeric PINs using crunch
```

```
Use brutespray to automatically brute-force all services found in my nmap XML output
```

---

## 5. OSINT & Information Gathering

### Domain Intelligence

```
Find all subdomains, emails, and hosts for target.com using theHarvester
```

```
Enumerate subdomains of target.com using amass in passive mode
```

```
Run subfinder and assetfinder on target.com and compare results
```

```
Find lookalike/typosquat domains for mycompany.com using dnstwist
```

### DNS Reconnaissance

```
Do a full DNS enumeration on target.com with dnsenum
```

```
Run dnsrecon on target.com checking for zone transfers
```

```
Look up all DNS records for target.com — A, AAAA, MX, NS, TXT, SOA
```

```
Brute-force subdomains of target.com using dnsmap
```

### WHOIS & IP Intelligence

```
Do a WHOIS lookup on target.com
```

```
Get Shodan information for IP 93.184.216.34
```

```
Search Shodan for Apache servers running on port 8080 in the US
```

### People & Social OSINT

```
Search for the username "johndoe2024" across social media platforms using Sherlock
```

```
Run SpiderFoot OSINT scan on the domain target.com
```

### Network Services

```
Enumerate SNMP info on 10.0.0.1 with community string "public"
```

```
Scan 10.0.0.0/24 for SNMP services with common community strings using onesixtyone
```

```
Enumerate SMB shares and users on 10.0.0.5 using enum4linux
```

### HTTP Probing

```
Check which of these subdomains are live: sub1.target.com, sub2.target.com, api.target.com
```

```
Run naabu to quickly find open ports on target.com
```

---

## 6. Active Directory & Windows

### Enumeration

```
Use crackmapexec to enumerate SMB on 10.0.0.0/24 and list accessible shares
```

```
List SMB shares on 10.0.0.5 as anonymous user
```

```
Enumerate valid AD usernames on domain CORP.LOCAL against DC 10.0.0.1 using kerbrute
```

```
Dump LDAP domain info from DC 10.0.0.1 with credentials admin:Password123
```

### Credential Attacks

```
Try AS-REP roasting on CORP.LOCAL domain against DC 10.0.0.1
```

```
Kerberoast the domain CORP.LOCAL using credentials jsmith:Summer2024 against DC 10.0.0.1
```

```
Password spray "Welcome1!" against AD users on CORP.LOCAL using kerbrute
```

### Lateral Movement

```
Use impacket psexec to run "whoami" on 10.0.0.5 as CORP/admin:Password1
```

```
Execute "ipconfig /all" on 10.0.0.5 via WMI using admin credentials
```

```
Dump secrets (SAM/LSA/NTDS) from 10.0.0.5 with admin:Password1 using secretsdump
```

### Hash Capture

```
Start Responder in analyze mode on eth0 to see LLMNR/NBT-NS traffic
```

```
Collect BloodHound data from CORP.LOCAL using credentials jsmith:Password1
```

---

## 7. Exploitation

### Exploit Research

```
Search exploitdb for Apache 2.4 vulnerabilities
```

```
Search for WordPress 6.0 exploits in exploit-db
```

```
Show me the source code of exploit 50383 from exploit-db
```

### Metasploit

```
Use Metasploit to scan SSH version on 10.0.0.5
```

```
Run the Metasploit auxiliary module for SMB version scanning against 10.0.0.0/24
```

```
Generate a Linux reverse TCP meterpreter payload for 10.0.0.100:4444 in ELF format
```

### Vulnerability Scanning

```
Run nmap vulnerability scripts against 10.0.0.5 on all common ports
```

```
Use nmap to run all SMB vulnerability scripts on 10.0.0.5
```

---

## 8. Wireless & WiFi Cracking

### Scanning

```
Put wlan0 into monitor mode
```

```
Scan for nearby WiFi networks using airodump-ng on wlan0mon
```

```
Scan for WiFi networks on channel 6 only
```

### Capturing Handshakes

```
Capture packets from AP with BSSID AA:BB:CC:DD:EE:FF on channel 6
```

```
Send 10 deauth frames to AP AA:BB:CC:DD:EE:FF to force a handshake
```

```
Capture PMKID from nearby networks using hcxdumptool on wlan0
```

### Cracking WiFi Passwords

```
Crack the WPA handshake in /opt/uts-mcp/output/capture-01.cap using rockyou.txt
```

```
Convert the pcapng capture to hashcat format and crack with hashcat mode 22000
```

```
Use pyrit to crack the WPA handshake for network "HomeWiFi" with rockyou.txt
```

```
Run the full WiFi cracking pipeline against AP AA:BB:CC:DD:EE:FF on channel 6
```

### WPS Attacks

```
Run a Pixie Dust WPS attack against AP AA:BB:CC:DD:EE:FF using reaver
```

```
Try WPS brute-force on AP AA:BB:CC:DD:EE:FF using bully
```

### Advanced Wireless

```
Run automated wireless auditing with wifite on wlan0, WPA networks only
```

```
Change my MAC address to a random one on wlan0
```

```
Show my current MAC address on wlan0
```

---

## 9. Sniffing & Spoofing

```
Start bettercap on eth0 to do network reconnaissance
```

```
Sniff passwords on eth0 using dsniff
```

```
Run ARP spoofing between 10.0.0.5 and the gateway 10.0.0.1 on eth0
```

```
Start mitm6 IPv6 attack on domain CORP.LOCAL
```

```
Passively fingerprint operating systems on eth0 using p0f
```

---

## 10. Network Analysis

### Packet Capture

```
Capture 200 packets on eth0 filtering for HTTP traffic on port 80
```

```
Read the pcap file at /opt/uts-mcp/output/capture.pcap with verbose output
```

```
Analyze /opt/uts-mcp/output/capture.pcap with tshark, show only HTTP requests
```

### Network Utilities

```
Set up a TCP port forward from local port 8080 to 10.0.0.5:80 using socat
```

```
Run nmap through proxychains to scan 10.0.0.5
```

```
Test network bandwidth to 10.0.0.1 using iperf3
```

```
Capture and decode SSL traffic on eth0 port 443 using ssldump
```

---

## 11. Forensics & Steganography

### File Analysis

```
Analyze suspicious.bin with binwalk to find embedded files
```

```
Recover deleted files from disk.img using foremost, looking for jpg and pdf files
```

```
Carve files from disk_image.dd using scalpel
```

```
Identify what type of file unknown_file is
```

### Disk Forensics

```
List all files in the disk image evidence.dd using sleuthkit
```

```
Show the partition layout of evidence.dd
```

```
Extract the file at inode 12345 from evidence.dd
```

### Memory Forensics

```
Analyze memory.dmp with volatility3, list all running processes
```

```
Use volatility3 to extract password hashes from windows_memory.dmp
```

```
Scan memory.dmp for network connections using volatility3 windows.netscan
```

### Steganography

```
Check if there's hidden data in image.jpg using steghide
```

```
Extract hidden data from image.jpg with passphrase "secret123"
```

```
Try to brute-force the steghide passphrase on image.jpg using rockyou.txt
```

```
Extract hidden data from picture.jpg using outguess
```

### Metadata

```
Extract all metadata from document.pdf using exiftool
```

```
Show hex dump of the first 512 bytes of mystery_file
```

```
Extract all printable strings from suspicious.exe with minimum length 8
```

### Archive Cracking

```
Crack the password on protected.pdf using pdfcrack with rockyou.txt
```

```
Brute-force the password on secret.zip using fcrackzip
```

### Malware Detection

```
Scan /opt/uts-mcp/output/ for malware signatures using YARA rules
```

```
Run bulk_extractor on disk.img to find emails, URLs, and credit card numbers
```

---

## 12. Reverse Engineering

```
Analyze the binary /opt/uts-mcp/output/malware with radare2 — list functions and disassemble main
```

```
Analyze binary.elf with rizin, show function list and imports
```

```
Disassemble /opt/uts-mcp/output/binary using objdump with Intel syntax
```

```
Trace system calls of the command "ls -la" using strace
```

```
Trace library calls of "./program" using ltrace
```

```
Run GDB on /opt/uts-mcp/output/crackme and list all functions
```

### Mobile

```
Decode the Android APK at /opt/uts-mcp/output/app.apk using apktool
```

```
Convert /opt/uts-mcp/output/app.apk to a JAR file using dex2jar
```

### Unpacking

```
Unpack the UPX-compressed binary at /opt/uts-mcp/output/packed.exe
```

---

## 13. Vulnerability Scanning

```
Run a Lynis security audit on this system
```

```
Check for rootkits using chkrootkit
```

```
Scan for rootkits and backdoors using rkhunter
```

```
Scan /opt/uts-mcp/output/ for malware with ClamAV
```

```
Run nmap with the http-enum script against 10.0.0.5 port 80
```

---

## 14. Database Assessment

```
Run ODAT against Oracle DB at 10.0.0.10 to discover SIDs
```

```
Guess Oracle SIDs on 10.0.0.10 port 1521
```

```
Probe the Oracle TNS listener on 10.0.0.10
```

```
Test for blind SQL injection on https://target.com/search?q=test using bbqsql
```

```
Audit database passwords on MySQL at 10.0.0.10 using dbpwaudit
```

---

## 15. VoIP Security

```
Scan 10.0.0.0/24 for SIP devices using svmap
```

```
Enumerate SIP extensions 100-500 on PBX at 10.0.0.20
```

```
Brute-force the password for SIP extension 200 on 10.0.0.20
```

```
Enumerate IAX2 usernames on Asterisk server 10.0.0.20
```

```
Run a SIP performance test against 10.0.0.20 with 10 calls at 1 call/sec
```

---

## 16. Cryptography & Encoding

### Hash Operations

```
What type of hash is this: $2y$10$abcdef1234567890abcdef
```

```
Generate an MD5 hash of "password123"
```

```
Generate SHA-256 hash of "mysecretvalue"
```

### Encoding/Decoding

```
Base64 encode the string "admin:password123"
```

```
Base64 decode "YWRtaW46cGFzc3dvcmQxMjM="
```

```
URL encode the string "test param=value&other=<script>"
```

```
Convert "hello world" to hexadecimal
```

```
Decode hex string "68656c6c6f" back to text
```

---

## 17. Generating Reports

### After a Pentest — Structured Findings Report

```
Generate a professional HTML security report for the assessment of target.com.

Title: "Web Application Penetration Test — target.com"
Target: target.com
Tester: Security Team
Scope: External web application assessment

Executive Summary: A penetration test was conducted on target.com's web application.
Testing identified 2 critical, 3 high, and 5 medium severity vulnerabilities including
SQL injection, cross-site scripting, and outdated SSL/TLS configurations.

Findings:
[
  {
    "title": "SQL Injection in Login Form",
    "severity": "critical",
    "description": "The login form at /login is vulnerable to SQL injection via the username parameter.",
    "evidence": "sqlmap identified the parameter as injectable. Payload: admin' OR '1'='1",
    "recommendation": "Use parameterized queries. Implement input validation.",
    "references": "OWASP Top 10 A03:2021, CWE-89"
  },
  {
    "title": "TLS 1.0 and 1.1 Enabled",
    "severity": "high",
    "description": "The server supports deprecated TLS 1.0 and TLS 1.1 protocols.",
    "evidence": "testssl.sh confirmed TLS 1.0 and 1.1 are accepted.",
    "recommendation": "Disable TLS 1.0 and 1.1. Only allow TLS 1.2+ with strong cipher suites.",
    "references": "NIST SP 800-52, PCI DSS 3.2.1"
  },
  {
    "title": "Missing Security Headers",
    "severity": "medium",
    "description": "HSTS, CSP, and X-Content-Type-Options headers are missing.",
    "evidence": "curl -sI showed no HSTS or CSP headers present.",
    "recommendation": "Add Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options headers.",
    "references": "OWASP Secure Headers Project"
  }
]
```

### After a Scan — Raw Tool Output Report

```
Generate a scan report in PDF format from the nmap and nikto results I just ran.

Title: "Network Security Scan Report"
Target: 192.168.1.0/24
Scope: Internal network assessment

Tool results:
[
  {
    "tool_name": "nmap_scan",
    "target": "192.168.1.0/24",
    "command": "nmap -sV -p 1-1000 192.168.1.0/24",
    "output": "(paste the nmap output here)",
    "elapsed": 45.2
  },
  {
    "tool_name": "nikto_scan",
    "target": "192.168.1.100",
    "command": "nikto -h 192.168.1.100 -ssl",
    "output": "(paste the nikto output here)",
    "elapsed": 120.5
  }
]
```

### Other Report Formats

```
Generate the same report but in Markdown format
```

```
Create a CSV export of all findings for the spreadsheet team
```

```
Export the report as JSON for our ticketing system
```

### Managing Reports

```
List all generated reports
```

```
Read the contents of the report at /opt/uts-mcp/reports/report_target.com_20260315.html
```

```
Convert the HTML report to PDF
```

---

## 18. Utilities & General Commands

### System & File Management

```
Show system info for the Unified ThreatLens container — OS, network, disk space
```

```
List all files in the output directory
```

```
Read the contents of /opt/uts-mcp/output/scan_results.txt
```

```
List all available wordlists
```

### HTTP Requests

```
Make a GET request to https://api.target.com/v1/users with header "Authorization: Bearer token123"
```

```
Send a POST request to https://target.com/api/login with data {"user":"admin","pass":"test"}
```

```
Download the file at https://example.com/backup.zip to the output directory
```

### Networking

```
Calculate the network info for 192.168.1.0/24
```

```
Run a custom command: "cat /etc/passwd" inside the Unified ThreatLens container
```

---

## 19. Database & Pattern Updates

Many security tools rely on up-to-date databases, signatures, and vulnerability templates to be effective. The Unified ThreatLens MCP server stores all tool databases on a **persistent Docker volume** (`cybertool-mcp-data`), so updates survive container restarts and image rebuilds.

### How Persistence Works

| Component | What it stores | Persistent path |
|---|---|---|
| **Docker volume** `cybertool-mcp-data` | All tool databases | `/opt/uts-mcp/data/` |
| **Entrypoint auto-update** | Runs full update on first boot | Controlled by `AUTO_UPDATE` env var |
| **Symlinks** | Point tools to persistent data | Set up automatically at container start |

The `AUTO_UPDATE` environment variable controls when automatic updates happen:
- `first` (default) — update only on the very first container start (when no stamp file exists)
- `always` — update every time the container starts
- `never` — skip all automatic updates

### Which Tools Get Updated

| Tool | What's updated |
|---|---|
| **Nmap** | NSE scripts, service probes, OS detection DB |
| **Metasploit** | Exploit modules and framework |
| **Nuclei** | YAML vulnerability templates |
| **WPScan** | WordPress vulnerability database |
| **ClamAV** | Virus signature database |
| **ExploitDB / SearchSploit** | Exploit CSV indices |
| **Nikto** | Scan plugins and databases |
| **rkhunter** | Rootkit definitions |
| **Lynis** | Security audit definitions |
| **Subfinder** | Provider configuration |
| **Amass** | Data source configuration |
| **Wapiti** | Vulnerability modules |
| **Hashcat** | Rule files |

### Checking Update Status

```
Show the status of all tool database updates — when was each tool last updated?
```

```
Check if my security tool databases are current
```

### Updating All Databases at Once

```
Update all tool databases and signatures to the latest versions
```

```
Refresh every security tool database — Nmap scripts, Nuclei templates, ClamAV sigs, everything
```

### Updating a Single Tool

```
Update only the Nmap scripts and service probes
```

```
Update the Nuclei vulnerability templates
```

```
Refresh the ClamAV virus signatures
```

```
Update the WPScan WordPress vulnerability database
```

```
Update Metasploit framework and exploit modules
```

```
Update the ExploitDB / SearchSploit database
```

```
Update Nikto scan plugins
```

### Best Practice: Update Before Major Assessments

```
I'm about to run a full security assessment on target.com.
First, update all tool databases, then run a comprehensive scan.
```

This ensures you are testing against the latest known vulnerabilities.

---

## 20. Post-Quantum Cryptography (PQC) Assessment

As quantum computing advances, classical cryptographic algorithms (RSA, ECDSA, DH, ECDH) will become vulnerable to Shor's algorithm. The Unified ThreatLens MCP server includes dedicated tools to assess your servers' readiness for the post-quantum era.

### Full PQC Readiness Assessment

Run a comprehensive scored assessment (0–100) covering TLS 1.3 support, PQC key exchange groups, certificate quantum-vulnerability, and testssl.sh PQC findings:

```
Run a full post-quantum cryptography readiness assessment on example.com
```

This produces a detailed report with a readiness score, risk level (NONE / LOW / MODERATE / HIGH), and actionable migration recommendations.

### Probe PQC Key Exchange Groups

Test whether a server supports specific post-quantum hybrid key exchange groups like X25519Kyber768 or ML-KEM:

```
Probe example.com for post-quantum key exchange support — test Kyber and ML-KEM groups
```

### Certificate Quantum-Vulnerability Check

Analyse a TLS certificate to determine if it uses quantum-vulnerable classical algorithms or PQC algorithms:

```
Check if example.com's certificate is vulnerable to quantum attacks
```

### Quick Quantum Risk Summary

Get a rapid risk rating and migration checklist for any TLS endpoint:

```
Give me a quick quantum risk summary for example.com
```

This returns a risk level (CRITICAL / HIGH / MEDIUM / LOW), "harvest now, decrypt later" exposure flag, and a step-by-step migration checklist.

### PQC-Filtered Scans with testssl.sh and SSLyze

Run standard SSL scanners with PQC-focused filtering:

```
Run testssl.sh on example.com and filter for any post-quantum cryptography findings
```

```
Scan example.com with SSLyze and check for PQC support in TLS 1.3
```

### Chaining PQC with Full SSL Assessment

Combine PQC assessment with the existing SSL vulnerability checks for a complete picture:

```
Run a full SSL security assessment on example.com:
1. Check for classical vulnerabilities (Heartbleed, POODLE, ROBOT)
2. Run a post-quantum cryptography readiness assessment
3. Generate a professional report with both classical and PQC findings
```

### What the PQC Tools Check

| Aspect | What's Tested |
|--------|--------------|
| **TLS 1.3** | Required for PQC key exchange — is it enabled? |
| **Hybrid KEX** | X25519Kyber768, X25519_MLKEM768, secp256r1_MLKEM768, secp384r1_MLKEM1024 |
| **Pure PQC KEX** | Kyber512/768/1024, ML-KEM-512/768/1024 |
| **Certificate Signatures** | ML-DSA (Dilithium), Falcon, SLH-DSA (SPHINCS+) |
| **Classical Vulnerability** | RSA, ECDSA, Ed25519/Ed448, DSA — all vulnerable to Shor's algorithm |
| **HNDL Risk** | "Harvest Now, Decrypt Later" — is current traffic at risk of future decryption? |

### NIST PQC Standards Reference

| FIPS | Algorithm | Use |
|------|-----------|-----|
| **FIPS 203** | ML-KEM (Kyber) | Key Encapsulation |
| **FIPS 204** | ML-DSA (Dilithium) | Digital Signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Stateless Hash-Based Signatures |

---

## 21. Disk Incident Response (Remote & Attached Disk)

Use these tools when a Linux server suddenly reaches 96-100% disk usage, or when a source disk is physically detached and attached to an analysis server for read-only root-cause analysis.

### 0) One-Time SSH Onboarding (Recommended)

To streamline all remote MCP functions, generate one persistent keypair in the container and install the public key on each remote Linux target.

```
Generate a remote SSH keypair for MCP and show me the public key and setup commands
```

Then validate remote access before running any disk function:

```
Run SSH preflight check on 10.10.20.15 as user incidentops and verify sudo is ready
```

Tips:
- Keep keys under `/opt/uts-mcp/data/ssh-keys` (persistent volume).
- Set `REMOTE_SSH_KEY_PATH` to avoid passing `ssh_key_path` every call.
- Use dedicated least-privilege account(s) and restrict sudo commands where possible.

### 1) Remote Live Triage (Non-Destructive)

Runs over SSH on the remote Linux host and checks:
- filesystem and inode pressure
- top directory and file growth
- deleted-but-open files (`lsof +L1`)
- log/journal growth
- Docker storage growth

```
Run remote Linux disk triage on 10.10.20.15 using user root and SSH key /opt/uts-mcp/data/keys/prod_id_rsa.
```

### 2) Remote Remediation Plan (No Changes Applied)

Builds a prioritized action plan based on triage output.

```
Create a disk remediation plan for 10.10.20.15 based on the latest triage results.
```

### 3) Remote Cleanup (Requires Explicit Confirmation)

This can modify the remote host. The MCP function refuses to run without explicit confirmation.

```
Run conservative cleanup on 10.10.20.15 with confirm=true:
- vacuum journal to 7 days
- force logrotate
- apt cache clean
- do not prune docker yet
```

Example with optional Docker cleanup:

```
Run remote cleanup on 10.10.20.15 with confirm=true and prune_docker=true.
```

### 4) Remote Forensic Disk Imaging

Create a forensic image directly on the remote host using `dc3dd` or `ddrescue`.

```
Create a forensic image of /dev/sdb on remote host 10.10.20.15 using dc3dd,
save to /evidence/serverA_sdb.img, hash with sha256.
```

### 5) Attached Disk Root-Cause Analysis (Your New Use Case)

When the source disk is removed from the original server and attached to a separate Linux analysis host:

- identify device and partition table
- detect filesystem types
- mount partitions read-only using safe fs-specific flags
- analyze top space consumers and likely root-cause hotspots

```
Analyze attached disk /dev/sda on remote host 10.10.30.9.
It has partitions /dev/sda1 and /dev/sda2.
Mount read-only under /mnt/forensics and find why it became full.
```

### 6) Attached Disk Compromise Investigation (Offline Forensics)

This performs compromise-focused checks on the mounted offline OS disk:
- successful SSH logins (`Accepted password/publickey`)
- sudo/su privilege escalation traces
- UID 0 account anomalies
- persistence checks (`authorized_keys`, cron, suspicious systemd units)
- suspicious IOC-like files in high-risk paths
- log tamper hints

```
Run attached disk compromise investigation on remote host 10.10.30.9 for /dev/sda.
Mount read-only under /mnt/forensics and generate a JSON report.
```

### Safety Notes for Attached Disk Analysis

- Do not assume `/dev/sda` is always the attached source disk.
- The function includes a guard to refuse analysis if the selected disk appears to be the current OS root disk.
- Partitions are mounted read-only (`ro`, `noload`/`norecovery` where applicable).
- If partitions are encrypted (`crypto_LUKS`) or LVM-only (`LVM2_member`), manual unlock/activation may be required before content analysis.

### Typical Root Causes Found

- runaway logs in `/var/log`
- large container layers/logs in `/var/lib/docker` or `/var/lib/containerd`
- unexpected backup dumps (`*.tar`, `*.sql`, `*.gz`, `*.bak`)
- large crash/core dump files
- cache/temp accumulation in `/tmp`, `/var/tmp`, package caches
- inode exhaustion from very high file counts

---

## 22. Chaining Tools Together

The real power comes from asking Claude to combine multiple tools in sequence. Here are some examples of full assessment workflows:

### Full Web Application Assessment

```
Perform a complete web application security assessment on https://target.com:

1. First, identify what technologies it uses
2. Check if there's a WAF protecting it
3. Run a full SSL/TLS assessment
4. Check all security headers
5. Scan for web vulnerabilities with nikto
6. Run nuclei for known CVEs
7. Brute-force directories with ffuf
8. Test for SQL injection on any forms found
9. Generate a professional HTML report with all findings
```

### Internal Network Pentest

```
I need to do an internal network assessment on 10.0.0.0/24:

1. Discover all live hosts with ARP scan
2. Port scan all discovered hosts for common ports
3. Identify services and versions on open ports
4. Check for SMB vulnerabilities
5. Enumerate any Windows/SMB shares
6. Run vulnerability scripts on all web servers found
7. Check for default credentials on SSH, FTP, and web services
8. Generate a report of everything found
```

### SSL/TLS Security Audit

```
Do a complete SSL/TLS security audit on our domains:

1. Check certificate validity and expiry for api.company.com
2. Show the full certificate chain
3. Enumerate all supported ciphers
4. Test for TLS 1.0/1.1 support (should be disabled)
5. Check for Heartbleed, POODLE, ROBOT, and CCS injection
6. Verify HSTS is enabled
7. Check all HTTP security headers
8. Run testssl.sh for the full picture
9. Create a PDF report with findings and recommendations
```

### WiFi Security Assessment

```
I need to test the WiFi security of our office network:

1. Put wlan0 into monitor mode
2. Scan for all nearby WiFi networks
3. Identify our target network "OfficeWiFi" and its BSSID and channel
4. Capture a WPA2 handshake from that network
5. Try cracking it with rockyou.txt using aircrack-ng
6. If that fails, convert to hashcat format and try with hashcat
7. Generate a report of the results
```

---

## 23. Tips & Best Practices

### Getting Better Results

- **Be specific about targets.** Include IPs, ports, URLs, and protocols.
- **Mention the tool by name** if you have a preference: "use nuclei" vs "use nikto."
- **Set timeouts** for large scans: "scan with a 10-minute timeout."
- **Ask for HTTPS explicitly** if testing SSL sites: "scan https://target.com."

### Working with Output

- Tool results are saved in `/opt/uts-mcp/output/` — ask Claude to list or read them.
- Reports go to `/opt/uts-mcp/reports/`.
- You can ask Claude to save any output: "save those nmap results to a file."

### Safety

- Always mention you have authorization: "I have permission to test 10.0.0.5."
- Start with passive/non-intrusive scans before aggressive testing.
- Use scan rate limits on production systems: "scan at 100 packets/sec."
- Review what Claude is about to run before confirming tool execution.

### Report Workflow

The most effective pattern for reports:

1. Run your scans and attacks
2. Ask Claude to summarize findings with severity ratings
3. Ask Claude to generate a report — it will structure everything automatically
4. Request PDF format for client delivery, Markdown for internal wikis, CSV for tracking

```
Summarize everything we found today and generate a professional PDF penetration test
report. Include an executive summary, all findings sorted by severity, evidence from
our tool outputs, and remediation recommendations.
```

---

## 24. Dashboard Playbook Management

The dashboard now includes a **Playbook Management** panel for YAML-backed workflows.

### Persistence model

- Default playbook path: `/opt/uts-mcp/data/playbooks`
- Override path with `MCP_PLAYBOOKS_DIR`
- Seed behavior: `recon_external.yaml` is auto-created on first run if missing
- Run history: stored under the same playbook directory (`run_history.jsonl`)

### CRUD + clone workflow

1. Open dashboard and navigate to **Playbooks**.
2. Load existing playbook into the editor or create a new one by name.
3. Click **Validate** to run schema/dependency checks before saving.
4. Click **Save** to create/update YAML in persistent storage.
5. Use **Clone** to copy an existing playbook to a new name and edit safely.
6. Use **Delete** for soft-delete (recoverable from `.trash`).

### Run integration

- Playbooks are executed from AI chat using MCP tool `run_playbook(...)`.
- Dashboard is for authoring/validation/versioning and run-history visibility.
- Each run emits per-step audit events and records run history.
- Review execution via:
  - dashboard run-history endpoint: `GET /api/playbooks/<name>/runs`
  - audit timeline in Session view

Example AI invocation:
- `run_playbook(name="recon_external", target="192.168.0.36", variables_json="{}")`

### API reference for playbook UI

- `GET /api/playbooks`
- `GET /api/playbooks/<name>`
- `POST /api/playbooks`
- `PUT /api/playbooks/<name>`
- `DELETE /api/playbooks/<name>`
- `POST /api/playbooks/<name>/clone`
- `POST /api/playbooks/<name>/validate`
- `GET /api/playbooks/<name>/runs?limit=50`

### Troubleshooting validation errors

- `Duplicate step id`: ensure each `steps[].id` is unique.
- `Unknown dependency`: ensure each `depends_on` step exists.
- YAML parse errors: validate indentation, list syntax, and quoting.
- Version conflict on save: refresh the latest YAML and retry.

---

## Quick Reference — What to Say

| I want to... | Say this to Claude |
|---|---|
| Scan ports | "Scan 10.0.0.5 for open ports" |
| Find subdomains | "Find all subdomains of target.com" |
| Test for SQLi | "Test https://target.com/page?id=1 for SQL injection" |
| Check SSL | "Run a full SSL security check on target.com" |
| Crack a hash | "Identify and crack this hash: 5f4dcc..." |
| Brute-force SSH | "Brute-force SSH on 10.0.0.5 with user admin" |
| Crack WiFi | "Crack the WPA handshake in capture.cap" |
| Scan WordPress | "Scan https://blog.target.com for WordPress vulnerabilities" |
| Check headers | "Check security headers on https://target.com" |
| AD enumeration | "Enumerate SMB shares on 10.0.0.0/24" |
| Memory forensics | "Analyze memory.dmp for processes and passwords" |
| Extract hidden data | "Check image.jpg for steganography" |
| Reverse engineer | "Disassemble and analyze binary.elf" |
| Generate report | "Create an HTML pentest report with our findings" |
| Run anything | "Run the command nmap -A 10.0.0.5 in the Unified ThreatLens container" |
