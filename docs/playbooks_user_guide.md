# Playbooks User Guide

This guide explains how to run the example playbooks, including authenticated web testing with username/password and session cookie variables.

## Included examples

- `recon_external.yaml`
- `incident_triage_memory.yaml`
- `service_vuln_baseline.yaml`
- `webapp_pentest_full.yaml`
- `api_pentest_owasp_top10.yaml`
- `tls_exposure_audit.yaml`
- `webapp_authenticated_deep_scan.yaml`
- `burpsuite_targeted_pipeline.yaml`
- `internal_network_pentest_ad.yaml`

## Key concept: template variables

Playbook step arguments support `{{variable_name}}` placeholders.

- `{{target}}` is always available from run input.
- Additional variables can be provided at run time (for example `username`, `password`, `session_cookie`, `domain`, `dc_host`).

Examples:

- `url: "{{target}}{{login_path}}"`
- `data: "username={{username}}&password={{password}}"`
- `headers: "Cookie: {{session_cookie}}"`

## Run from dashboard

1. Open **Playbooks** tab.
2. Click **Run** on the playbook.
3. Provide target.
4. When prompted for optional variables JSON, provide an object like:

```json
{
  "login_path": "/login",
  "auth_base_path": "/app",
  "username": "tester",
  "password": "ChangeMe!",
  "session_cookie": "sessionid=abc123",
  "sqli_test_path": "/app/orders?id=1"
}
```

## Run via API

`POST /api/playbooks/{name}/run`

Body:

```json
{
  "target": "https://target.example",
  "variables": {
    "username": "tester",
    "password": "ChangeMe!",
    "session_cookie": "sessionid=abc123"
  }
}
```

## Run via MCP tool

Use `run_playbook(name, target, variables_json)` where `variables_json` is a JSON object string.

Example:

```text
run_playbook(
  name="webapp_authenticated_deep_scan",
  target="https://target.example",
  variables_json="{\"login_path\":\"/login\",\"auth_base_path\":\"/app\",\"username\":\"tester\",\"password\":\"ChangeMe!\",\"session_cookie\":\"sessionid=abc123\",\"sqli_test_path\":\"/app/orders?id=1\"}"
)
```

## Notes for authenticated scans

- Prefer dedicated least-privileged test accounts.
- Obtain session cookies through approved login workflows.
- Avoid production-impacting checks in business hours.
- Keep explicit authorization for authenticated testing scope.

## Notes for internal AD scans

For `internal_network_pentest_ad.yaml`, provide:

- `domain` (for example `corp.local`)
- `dc_host` (for example `10.10.10.5`)
- `username` and `password`

`target` can be a CIDR (for example `10.10.10.0/24`) for broader discovery.
