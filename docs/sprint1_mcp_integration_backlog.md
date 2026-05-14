# Sprint 1 MCP Integration Backlog (P1 Tools)

## Scope
This backlog defines **ready-to-implement** work items for the first integration sprint of additional cybersecurity tools into the existing Python MCP server.

Baseline conventions:
- One MCP function per tool (`snake_case`).
- `timeout: int = 300` on every wrapper.
- Return `stdout + stderr` combined as a single string.
- Validate inputs and build command arguments as a list (no shell interpolation).

---

## 1) Photon
- **Function:** `run_photon(url: str, depth: int = 2, threads: int = 2, only_urls: bool = False, timeout: int = 300) -> str`
- **Binary/Entry:** `/opt/Photon/photon.py`
- **Command:** `python3 /opt/Photon/photon.py -u <url> -d <depth> -t <threads> [--only-urls]`
- **Validation:**
  - `url` must start with `http://` or `https://`
  - `depth` in `1..10`, `threads` in `1..20`
- **Acceptance Criteria:**
  1. Invalid URL returns validation error string.
  2. Successful run returns discovered crawl output.
  3. Timeout path returns standard timeout marker.
- **Estimate:** Low

## 2) Holehe
- **Function:** `run_holehe(email: str, only_used: bool = True, timeout: int = 300) -> str`
- **Command:** `holehe <email> [--only-used]`
- **Validation:** RFC-like simple email pattern.
- **Acceptance Criteria:**
  1. Invalid email blocked before execution.
  2. Output includes service hit/miss lines.
- **Estimate:** Low

## 3) Arjun
- **Function:** `run_arjun(url: str, methods: str = "GET,POST", wordlist: str | None = None, timeout: int = 300) -> str`
- **Command:** `arjun -u <url> -m <methods> [--wordlist <path>]`
- **Validation:**
  - methods subset of `{GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH}`
  - optional wordlist must exist.
- **Acceptance Criteria:**
  1. Valid scan prints found params.
  2. Bad method value rejected with friendly error.
- **Estimate:** Low

## 4) ParamSpider
- **Function:** `run_paramspider(domain: str, exclude: str | None = None, timeout: int = 300) -> str`
- **Entry:** `/opt/ParamSpider/paramspider.py`
- **Command:** `python3 /opt/ParamSpider/paramspider.py --domain <domain> [--exclude <csv>]`
- **Validation:** domain format and safe char allowlist.
- **Acceptance Criteria:** output includes completion status and output file path.
- **Estimate:** Low

## 5) LinkFinder
- **Function:** `run_linkfinder(input_url: str, output_format: str = "cli", timeout: int = 300) -> str`
- **Entry:** `/opt/LinkFinder/linkfinder.py`
- **Command:** `python3 /opt/LinkFinder/linkfinder.py -i <input_url> -o <output_format>`
- **Validation:** `output_format` in `{cli,html}`.
- **Acceptance Criteria:** raw endpoint discovery lines returned.
- **Estimate:** Low

## 6) SecretFinder
- **Function:** `run_secretfinder(input_url: str, regex_mode: bool = False, timeout: int = 300) -> str`
- **Entry:** `/opt/SecretFinder/SecretFinder.py`
- **Command:** `python3 /opt/SecretFinder/SecretFinder.py -i <input_url> [--regex]`
- **Validation:** URL scheme required.
- **Acceptance Criteria:** detection output returned; no crash on no-find case.
- **Estimate:** Low

## 7) Gitleaks
- **Function:** `run_gitleaks(path: str = ".", config: str | None = None, redact: bool = True, timeout: int = 300) -> str`
- **Command:** `gitleaks detect --source <path> [--config <path>] [--redact]`
- **Validation:** source path exists; config exists when set.
- **Acceptance Criteria:**
  1. Clean repo output still returns execution summary.
  2. Non-zero exit code still returns captured text.
- **Estimate:** Low

## 8) TruffleHog
- **Function:** `run_trufflehog(target: str, target_type: str = "filesystem", json: bool = True, timeout: int = 300) -> str`
- **Command:** `trufflehog filesystem <target> [--json]`
- **Validation:** `target_type` initially constrained to `filesystem`.
- **Acceptance Criteria:** line-delimited JSON is returned as string when enabled.
- **Estimate:** Low

## 9) Hashid
- **Function:** `run_hashid(hash_value: str, extended: bool = False, timeout: int = 300) -> str`
- **Command:** `hashid <hash_value> [--extended]`
- **Validation:** min hash length > 8.
- **Acceptance Criteria:** candidate hash types returned.
- **Estimate:** Low

## 10) Fail2Ban
- **Function:** `run_fail2ban_client(action: str = "status", jail: str | None = None, timeout: int = 300) -> str`
- **Command:** `fail2ban-client <action> [<jail>]`
- **Validation:** action allowlist: `status|get|set|reload`.
- **Acceptance Criteria:** handles permission/service-not-running errors gracefully.
- **Estimate:** Low

## 11) AIDE
- **Function:** `run_aide(mode: str = "check", config: str | None = None, timeout: int = 300) -> str`
- **Command:** `aide [--config <path>] --check|--init|--update`
- **Validation:** mode allowlist.
- **Acceptance Criteria:** returns integrity check summary and warnings.
- **Estimate:** Low

## 12) pwntools (script runner)
- **Function:** `run_pwntools_script(script_path: str, args: str | None = None, timeout: int = 300) -> str`
- **Command:** `python3 <script_path> [args...]`
- **Validation:** script exists under allowed workspace path.
- **Acceptance Criteria:** script output and tracebacks captured in returned text.
- **Estimate:** Low

## 13) ROPgadget
- **Function:** `run_ropgadget(binary_path: str, options: str | None = None, timeout: int = 300) -> str`
- **Command:** `ROPgadget --binary <binary_path> [options]`
- **Validation:** file exists; optional arguments parsed safely.
- **Acceptance Criteria:** gadget list lines returned.
- **Estimate:** Low

## 14) Trivy
- **Function:** `run_trivy(target: str, scan_type: str = "fs", severity: str | None = None, timeout: int = 300) -> str`
- **Command:** `trivy <scan_type> <target> --no-progress [--severity <levels>]`
- **Validation:** scan type allowlist `{fs,image,repo}`.
- **Acceptance Criteria:** vulnerability summary appears in output text.
- **Estimate:** Low

## 15) Grype
- **Function:** `run_grype(target: str, timeout: int = 300) -> str`
- **Command:** `grype <target>`
- **Validation:** non-empty target.
- **Acceptance Criteria:** CVE findings or clean result returned.
- **Estimate:** Low

## 16) Syft
- **Function:** `run_syft(target: str, output: str = "table", timeout: int = 300) -> str`
- **Command:** `syft <target> -o <output>`
- **Validation:** output allowlist `{table,json,spdx-json,cyclonedx-json}`.
- **Acceptance Criteria:** SBOM output appears in selected format.
- **Estimate:** Low

## 17) Checkov
- **Function:** `run_checkov(directory: str = ".", framework: str | None = None, timeout: int = 300) -> str`
- **Command:** `checkov -d <directory> [--framework <name>]`
- **Validation:** directory exists.
- **Acceptance Criteria:** policy check summary and failed checks returned.
- **Estimate:** Low

## 18) S3Scanner
- **Function:** `run_s3scanner(target: str, timeout: int = 300) -> str`
- **Command:** `s3scanner scan <target>` (or project-specific syntax after pinning implementation)
- **Validation:** target as bucket/domain/list file.
- **Acceptance Criteria:** accessible bucket findings returned.
- **Estimate:** Low
- **Note:** finalize against selected maintained repo.

## 19) kube-bench
- **Function:** `run_kube_bench(target: str = "node", timeout: int = 300) -> str`
- **Command:** `kube-bench [run mode flags]`
- **Validation:** mode allowlist per deployment profile.
- **Acceptance Criteria:** CIS benchmark result blocks returned.
- **Estimate:** Low

## 20) Sigma (rule conversion)
- **Function:** `run_sigma_convert(rule_path: str, target: str, timeout: int = 300) -> str`
- **Command:** `sigma convert -t <target> <rule_path>` (pySigma CLI)
- **Validation:** rule file exists; target backend allowlist.
- **Acceptance Criteria:** converted query text returned.
- **Estimate:** Low

## 21) APKLeaks
- **Function:** `run_apkleaks(apk_path: str, timeout: int = 300) -> str`
- **Command:** `apkleaks -f <apk_path>`
- **Validation:** `.apk` exists.
- **Acceptance Criteria:** leaks summary returned without crash on clean APK.
- **Estimate:** Low

## 22) Boofuzz
- **Function:** `run_boofuzz_script(script_path: str, timeout: int = 300) -> str`
- **Command:** `python3 <script_path>`
- **Validation:** script exists; ensure script-only execution in approved path.
- **Acceptance Criteria:** execution logs captured and returned.
- **Estimate:** Low

---

## Cross-Cutting Implementation Tasks
1. Add shared helper `run_cli_tool(cmd: list[str], timeout: int = 300) -> str` if not already present.
2. Add shared validators: URL, email, path-exists, allowlist enums.
3. Add tool registration entries in MCP server bootstrap.
4. Add smoke tests per wrapper using known-safe targets/mocks.
5. Update README tool catalog and usage samples.

## Definition of Done (Sprint 1)
- All 22 wrappers callable from MCP without server crash.
- Standard timeout behavior implemented consistently.
- Input validation returns user-readable error strings.
- Docker image builds with required binaries and Python deps.
- Minimal docs for each new tool function (purpose + key args + example).
