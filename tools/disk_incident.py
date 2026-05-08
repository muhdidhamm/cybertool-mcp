"""Disk incident response tools.

Provides remote Linux disk triage/remediation over SSH and read-only attached
disk analysis workflows for forensic-safe root-cause discovery.
"""

import json
import os
import re
import shlex
from pathlib import Path

from tools.helpers import run_command, sanitize_arg, save_output, validate_target
from tools.contracts import CloudTriageResult
from tools.time_utils import format_now_tz


_VALID_HASHES = {"md5", "sha1", "sha256", "sha512"}
_DEFAULT_KEY_DIR = "/opt/uts-mcp/data/ssh-keys"
_DEFAULT_PRIVATE_KEY = f"{_DEFAULT_KEY_DIR}/mcp_remote_ed25519"


def _validate_ssh_user(user: str) -> str:
    user = sanitize_arg(user).strip()
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.-]*$", user):
        raise ValueError(f"Invalid SSH username: {user}")
    return user


def _validate_device_path(device: str) -> str:
    device = sanitize_arg(device).strip()
    if not re.match(r"^/dev/[a-zA-Z0-9._/-]+$", device):
        raise ValueError(f"Invalid device path: {device}")
    return device


def _validate_abs_path(path: str) -> str:
    path = sanitize_arg(path).strip()
    if not path.startswith("/"):
        raise ValueError("Path must be absolute")
    return path


def _resolve_ssh_key_path(ssh_key_path: str = "") -> str:
    key_path = sanitize_arg(ssh_key_path).strip()
    if not key_path:
        key_path = sanitize_arg(os.environ.get("REMOTE_SSH_KEY_PATH", "")).strip()
    if not key_path:
        key_path = _DEFAULT_PRIVATE_KEY
    p = Path(key_path)
    if not p.exists():
        raise ValueError(
            f"SSH private key not found: {key_path}. "
            "Create one with ssh_keygen_for_remote_setup and install the public key on the target."
        )
    if p.is_dir():
        raise ValueError(f"SSH key path is a directory, expected a private key file: {key_path}")
    return str(p)


def _build_ssh_base(
    host: str,
    user: str,
    ssh_port: int,
    ssh_key_path: str = "",
    connect_timeout: int = 10,
) -> list[str]:
    host = validate_target(host)
    user = _validate_ssh_user(user)
    key_path = _resolve_ssh_key_path(ssh_key_path)
    base = [
        "ssh",
        "-p",
        str(int(ssh_port)),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={int(connect_timeout)}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        key_path,
    ]
    base.append(f"{user}@{host}")
    return base


async def _remote_exec(ssh_base: list[str], script: str, timeout: int = 60) -> dict:
    remote_cmd = f"bash -lc {shlex.quote(script)}"
    return await run_command(ssh_base + [remote_cmd], timeout=timeout)


def _parse_full_lines(df_text: str, threshold: int = 90) -> list[dict]:
    findings = []
    for line in df_text.splitlines():
        m = re.search(r"\s(\d+)%\s+(\S+)$", line.strip())
        if not m:
            continue
        pct = int(m.group(1))
        if pct >= threshold:
            findings.append({"use_percent": pct, "mountpoint": m.group(2), "line": line})
    return findings


def _deleted_open_count(lsof_text: str) -> int:
    count = 0
    for line in lsof_text.splitlines():
        if line.strip() and "COMMAND" not in line:
            count += 1
    return count


def _parse_sectioned_output(text: str) -> dict[str, str]:
    """Parse bash output formatted with ===SECTION:<name>=== markers."""
    sections: dict[str, list[str]] = {}
    current = "raw"
    sections[current] = []
    marker = re.compile(r"^===SECTION:([a-zA-Z0-9_.-]+)===$")
    for line in text.splitlines():
        m = marker.match(line.strip())
        if m:
            current = m.group(1)
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def _findings_from_offline_ioc_sections(sections: dict[str, str]) -> list[dict]:
    """Create normalized report findings from compromise investigation sections."""
    findings: list[dict] = []

    ssh_success = sections.get("ssh_success", "")
    if ssh_success and "No matching lines found" not in ssh_success:
        findings.append({
            "title": "Successful SSH authentication events found",
            "severity": "high",
            "description": (
                "Offline logs contain successful SSH login events "
                "(Accepted password/publickey). Validate source IPs, usernames, and times."
            ),
            "evidence": ssh_success[:6000],
            "recommendation": (
                "Correlate successful logins with approved admin windows and source IP allowlists. "
                "Rotate credentials/keys for suspicious accounts."
            ),
            "references": "MITRE ATT&CK T1078 (Valid Accounts)",
        })

    sudo_su = sections.get("sudo_su_events", "")
    if sudo_su and "No matching lines found" not in sudo_su:
        findings.append({
            "title": "Privilege escalation indicators in auth logs",
            "severity": "high",
            "description": "Sudo/su session events were identified and should be reviewed for abuse.",
            "evidence": sudo_su[:6000],
            "recommendation": "Review each privileged session against approved change activity and admin roster.",
            "references": "MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism)",
        })

    uid0 = sections.get("uid0_accounts", "")
    if uid0 and "No matching lines found" not in uid0:
        non_root_uid0 = [ln for ln in uid0.splitlines() if ln and not ln.startswith("root:")]
        if non_root_uid0:
            findings.append({
                "title": "Additional UID 0 accounts detected",
                "severity": "critical",
                "description": "Accounts other than root have UID 0 privileges.",
                "evidence": "\n".join(non_root_uid0)[:6000],
                "recommendation": (
                    "Immediately disable unexpected UID 0 accounts, preserve evidence, and reset privileged credentials."
                ),
                "references": "MITRE ATT&CK T1136 (Create Account)",
            })

    auth_keys = sections.get("authorized_keys_files", "")
    if auth_keys and "No authorized_keys files found" not in auth_keys:
        findings.append({
            "title": "Authorized keys present on mounted disk",
            "severity": "medium",
            "description": "SSH key-based persistence locations were found. Review for unauthorized keys.",
            "evidence": auth_keys[:6000],
            "recommendation": "Validate each key fingerprint against inventory; remove unknown keys and rotate trust material.",
            "references": "MITRE ATT&CK T1098 (Account Manipulation)",
        })

    cron = sections.get("cron_entries", "")
    if cron and "No cron entries found" not in cron:
        findings.append({
            "title": "Cron persistence locations populated",
            "severity": "medium",
            "description": "Scheduled task entries exist and may include persistence mechanisms.",
            "evidence": cron[:6000],
            "recommendation": "Review cron entries for suspicious commands (curl/wget/bash/python/nc) and remove malicious tasks.",
            "references": "MITRE ATT&CK T1053.003 (Cron)",
        })

    sysd = sections.get("systemd_suspicious", "")
    if sysd and "No suspicious systemd ExecStart patterns found" not in sysd:
        findings.append({
            "title": "Suspicious systemd service command patterns",
            "severity": "high",
            "description": "Systemd units contain command patterns often associated with persistence or payload retrieval.",
            "evidence": sysd[:6000],
            "recommendation": "Inspect flagged unit files, disable malicious services, and preserve copies for IR evidence.",
            "references": "MITRE ATT&CK T1543.002 (Systemd Service)",
        })

    ioc = sections.get("suspicious_ioc_files", "")
    if ioc and "No obvious suspicious IOC filenames found" not in ioc:
        findings.append({
            "title": "Suspicious IOC-like files detected",
            "severity": "high",
            "description": "Potential webshell/backdoor/miner artifacts found in mounted filesystem.",
            "evidence": ioc[:6000],
            "recommendation": "Hash and quarantine suspicious files, then perform malware triage (YARA/signature/static analysis).",
            "references": "MITRE ATT&CK T1505/T1105",
        })

    log_tamper = sections.get("log_tamper_hints", "")
    if log_tamper and "No clear tamper indicators" not in log_tamper:
        findings.append({
            "title": "Potential log tampering indicators",
            "severity": "medium",
            "description": "Authentication log files showed anomalies suggesting possible tamper or rotation inconsistency.",
            "evidence": log_tamper[:6000],
            "recommendation": "Cross-check with external log sources (SIEM/syslog) and preserve immutable backups.",
            "references": "MITRE ATT&CK T1070 (Indicator Removal on Host)",
        })

    if not findings:
        findings.append({
            "title": "No high-confidence compromise indicators found in offline scan",
            "severity": "info",
            "description": (
                "No strong indicators were detected from offline disk artifacts. "
                "This does not eliminate compromise; combine with memory/network/cloud telemetry."
            ),
            "evidence": "Offline checks completed with no major IOC/persistence hits.",
            "recommendation": "Correlate with SIEM, firewall, EDR, and cloud control-plane logs for higher confidence.",
            "references": "IR best practice",
        })

    return findings


def _normalize_cloud_triage(
    provider: str,
    target: str,
    command: str,
    result: dict,
    extra_meta: dict | None = None,
) -> dict:
    model = CloudTriageResult(
        provider=provider,
        target=target,
        command=command,
        success=bool(result.get("success", False)),
        stdout=str(result.get("stdout", "")),
        stderr=str(result.get("stderr", "")),
        evidence_meta=extra_meta or {},
    )
    return model.model_dump()


def register_disk_incident_tools(mcp):
    @mcp.tool()
    async def cloud_triage_aws_ssm(
        instance_id: str,
        command: str = "uname -a && df -hT && df -i",
        region: str = "us-east-1",
        timeout: int = 180,
    ) -> dict:
        """Run cloud disk triage command through AWS SSM and normalize evidence output.

        Requires AWS CLI credentials/environment configured in the runtime.
        """
        iid = sanitize_arg(instance_id).strip()
        region_value = sanitize_arg(region).strip() or "us-east-1"
        cmd = sanitize_arg(command).strip()
        if not iid:
            return {"success": False, "error": "instance_id is required"}
        if not cmd:
            return {"success": False, "error": "command is required"}

        payload = (
            '{"commands":["'
            + cmd.replace("\\", "\\\\").replace('"', '\\"')
            + '"]}'
        )
        result = await run_command(
            [
                "aws",
                "ssm",
                "send-command",
                "--instance-ids",
                iid,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                payload,
                "--region",
                region_value,
            ],
            timeout=timeout,
        )
        normalized = _normalize_cloud_triage(
            provider="aws",
            target=iid,
            command=cmd,
            result=result,
            extra_meta={"region": region_value, "execution": "ssm.send-command"},
        )
        report_path = save_output(
            f"cloud_triage_aws_{sanitize_arg(iid)}_{format_now_tz('%Y%m%d_%H%M%S')}.json",
            json.dumps(normalized, indent=2),
        )
        normalized["report_file"] = report_path
        return {"success": result.get("success", False), "normalized": normalized, "raw": result}

    @mcp.tool()
    async def cloud_triage_azure_vm_run_command(
        resource_group: str,
        vm_name: str,
        command: str = "uname -a && df -hT && df -i",
        timeout: int = 180,
    ) -> dict:
        """Run cloud disk triage command through Azure VM Run Command and normalize output.

        Requires Azure CLI credentials/environment configured in the runtime.
        """
        rg = sanitize_arg(resource_group).strip()
        vm = sanitize_arg(vm_name).strip()
        cmd = sanitize_arg(command).strip()
        if not rg or not vm:
            return {"success": False, "error": "resource_group and vm_name are required"}
        if not cmd:
            return {"success": False, "error": "command is required"}
        result = await run_command(
            [
                "az",
                "vm",
                "run-command",
                "invoke",
                "--resource-group",
                rg,
                "--name",
                vm,
                "--command-id",
                "RunShellScript",
                "--scripts",
                cmd,
            ],
            timeout=timeout,
        )
        normalized = _normalize_cloud_triage(
            provider="azure",
            target=f"{rg}/{vm}",
            command=cmd,
            result=result,
            extra_meta={"resource_group": rg, "vm_name": vm, "execution": "az.vm.run-command"},
        )
        report_path = save_output(
            f"cloud_triage_azure_{sanitize_arg(vm)}_{format_now_tz('%Y%m%d_%H%M%S')}.json",
            json.dumps(normalized, indent=2),
        )
        normalized["report_file"] = report_path
        return {"success": result.get("success", False), "normalized": normalized, "raw": result}

    @mcp.tool()
    async def ssh_keygen_for_remote_setup(
        key_name: str = "mcp_remote_ed25519",
        key_dir: str = _DEFAULT_KEY_DIR,
        rotate: bool = False,
    ) -> dict:
        """Generate and return an SSH keypair for remote MCP functions.

        Creates an ed25519 key under the persistent data volume, then returns
        public key content and ready-to-run setup commands for target systems.
        """
        key_name = sanitize_arg(key_name).strip() or "mcp_remote_ed25519"
        key_dir = _validate_abs_path(key_dir)
        private_key = f"{key_dir}/{key_name}"
        public_key = f"{private_key}.pub"

        mkdir = await run_command(["mkdir", "-p", key_dir], timeout=10)
        if not mkdir.get("success"):
            return mkdir

        exists = Path(private_key).exists()
        if exists and not rotate:
            pub_read = await run_command(["bash", "-lc", f"cat {shlex.quote(public_key)}"], timeout=10)
            return {
                "success": True,
                "message": "SSH key already exists (reused existing key).",
                "private_key_path": private_key,
                "public_key_path": public_key,
                "public_key": pub_read.get("stdout", "").strip(),
                "env_hint": f"Set REMOTE_SSH_KEY_PATH={private_key}",
                "remote_setup_steps": [
                    "Create remote account if needed (least privilege recommended).",
                    "Append the public key to ~/.ssh/authorized_keys on remote host.",
                    "Verify SSH + sudo with remote_ssh_preflight before running disk tools.",
                ],
            }

        gen_cmd = [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-a",
            "64",
            "-N",
            "",
            "-f",
            private_key,
            "-C",
            "uts-mcp-remote",
        ]
        generated = await run_command(gen_cmd, timeout=20)
        if not generated.get("success"):
            return generated

        chmod_key = await run_command(["chmod", "600", private_key], timeout=5)
        chmod_pub = await run_command(["chmod", "644", public_key], timeout=5)
        pub_read = await run_command(["bash", "-lc", f"cat {shlex.quote(public_key)}"], timeout=10)

        return {
            "success": True,
            "private_key_path": private_key,
            "public_key_path": public_key,
            "public_key": pub_read.get("stdout", "").strip(),
            "env_hint": f"Set REMOTE_SSH_KEY_PATH={private_key}",
            "remote_setup_steps": [
                "Install public key on target: mkdir -p ~/.ssh && chmod 700 ~/.ssh",
                "Append key to ~/.ssh/authorized_keys and chmod 600 ~/.ssh/authorized_keys",
                "Optional hardening: disable password auth in sshd_config after validation.",
            ],
            "permissions": {
                "private_key": chmod_key.get("success"),
                "public_key": chmod_pub.get("success"),
            },
        }

    @mcp.tool()
    async def remote_ssh_preflight(
        host: str,
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        require_sudo: bool = True,
    ) -> dict:
        """Validate key-based SSH access and optional passwordless sudo on remote host."""
        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        who = await _remote_exec(ssh_base, "id && hostname && uname -a", timeout=20)
        if not who.get("success"):
            return {
                "success": False,
                "error": "SSH connection failed. Verify key install, user, host, and network reachability.",
                "details": who,
            }

        sudo_ok = True
        sudo_result = {"success": True, "stdout": "sudo not requested"}
        if require_sudo:
            sudo_result = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            sudo_ok = sudo_result.get("success", False)

        return {
            "success": True if (who.get("success") and (sudo_ok or not require_sudo)) else False,
            "target": f"{user}@{host}:{int(ssh_port)}",
            "ssh_key_in_use": _resolve_ssh_key_path(ssh_key_path),
            "ssh_status": who,
            "sudo_required": require_sudo,
            "sudo_status": sudo_result,
            "ready_for_remote_disk_tools": who.get("success") and (sudo_ok or not require_sudo),
        }

    @mcp.tool()
    async def remote_linux_disk_triage(
        host: str,
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        use_sudo: bool = True,
        timeout: int = 240,
    ) -> dict:
        """Run non-destructive remote Linux disk triage over SSH.

        This checks disk usage, inode pressure, top directories/files, deleted-open
        files, logs, and container storage hotspots to identify why a filesystem
        suddenly became full.
        """
        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        sudo_prefix = ""
        warnings = []

        if use_sudo:
            sudo_test = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            if sudo_test.get("success"):
                sudo_prefix = "sudo -n "
            else:
                warnings.append("Passwordless sudo unavailable; running best-effort without sudo.")

        commands = {
            "df_hT": "df -hT",
            "df_i": "df -i",
            "lsblk": "lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT,PKNAME",
            "du_root": f"{sudo_prefix}du -xhd1 / 2>/dev/null | sort -h",
            "du_var": f"{sudo_prefix}du -xhd1 /var 2>/dev/null | sort -h",
            "lsof_deleted": f"{sudo_prefix}lsof +L1 2>/dev/null || true",
            "journal_usage": f"{sudo_prefix}journalctl --disk-usage 2>/dev/null || true",
            "log_dirs": f"{sudo_prefix}du -xhd1 /var/log 2>/dev/null | sort -h || true",
            "large_files": (
                f"{sudo_prefix}find / -xdev -type f -size +1G -printf '%s %p\\n' "
                "2>/dev/null | sort -nr | head -n 80"
            ),
            "docker_df": (
                "if command -v docker >/dev/null 2>&1; then "
                f"{sudo_prefix}docker system df; else echo 'docker: not installed'; fi"
            ),
            "docker_disk": (
                "if [ -d /var/lib/docker ]; then "
                f"{sudo_prefix}du -xhd1 /var/lib/docker 2>/dev/null | sort -h; "
                "else echo '/var/lib/docker missing'; fi"
            ),
        }

        results = {}
        per_cmd_timeout = max(20, min(90, int(timeout // max(1, len(commands)))))
        for name, script in commands.items():
            results[name] = await _remote_exec(ssh_base, script, timeout=per_cmd_timeout)

        df_full = _parse_full_lines(results["df_hT"].get("stdout", ""))
        inode_full = _parse_full_lines(results["df_i"].get("stdout", ""))
        deleted_open = _deleted_open_count(results["lsof_deleted"].get("stdout", ""))

        hypotheses = []
        if deleted_open > 0:
            hypotheses.append(
                f"Deleted-but-open files detected ({deleted_open} entries) are consuming hidden disk space."
            )
        if any(x["mountpoint"] == "/var" for x in df_full):
            hypotheses.append("/var appears full; likely log growth, package cache, or container data growth.")
        if "docker: not installed" not in results["docker_df"].get("stdout", ""):
            hypotheses.append("Docker/container storage may be contributing; inspect /var/lib/docker usage.")
        if not hypotheses and df_full:
            hypotheses.append("Filesystem is full; inspect top large files and recent writes for runaway processes.")
        if not hypotheses:
            hypotheses.append("No obvious single cause found; review command outputs for mixed contributors.")

        report = {
            "success": True,
            "target": f"{user}@{host}:{int(ssh_port)}",
            "warnings": warnings,
            "summary": {
                "full_filesystems_90pct_plus": df_full,
                "inode_pressure_90pct_plus": inode_full,
                "deleted_open_file_entries": deleted_open,
                "hypotheses": hypotheses,
            },
            "checks": {k: v.get("stdout", "") for k, v in results.items()},
            "raw": results,
        }

        report_path = save_output(
            f"remote_disk_triage_{sanitize_arg(host)}.json",
            json.dumps(report, indent=2),
        )
        report["report_file"] = report_path
        return report

    @mcp.tool()
    async def remote_linux_disk_remediate_plan(
        host: str,
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        use_sudo: bool = True,
    ) -> dict:
        """Generate a safe, prioritized remediation plan from remote disk triage data.

        This does not change the remote host. It only returns action steps and
        exact commands to run.
        """
        triage = await remote_linux_disk_triage(
            host=host,
            user=user,
            ssh_port=ssh_port,
            ssh_key_path=ssh_key_path,
            use_sudo=use_sudo,
            timeout=240,
        )
        if not triage.get("success"):
            return triage

        summary = triage.get("summary", {})
        steps = []
        steps.append("Capture snapshot first: df -hT, df -i, lsblk, and current alerts.")

        if summary.get("deleted_open_file_entries", 0) > 0:
            steps.append(
                "Release deleted-but-open files by restarting offending processes/services from lsof +L1 output."
            )
        if any(x.get("mountpoint") == "/var" for x in summary.get("full_filesystems_90pct_plus", [])):
            steps.append("Prioritize /var cleanup: logs, caches, crash dumps, and container runtime data.")
        if summary.get("inode_pressure_90pct_plus"):
            steps.append("Address inode exhaustion by deleting many tiny files (cache/session/tmp trees).")

        steps.extend([
            "Vacuum systemd journal and verify logrotate execution schedule.",
            "If Docker is used: prune unused images/containers/volumes after change approval.",
            "Set alerting thresholds (80/90/95%) and baseline growth tracking per mount.",
        ])

        commands = [
            "journalctl --disk-usage",
            "journalctl --vacuum-time=7d",
            "logrotate -f /etc/logrotate.conf",
            "apt-get clean",
            "lsof +L1",
            "docker system df",
            "docker system prune -f --volumes",
        ]

        return {
            "success": True,
            "target": triage.get("target"),
            "root_cause_hypotheses": summary.get("hypotheses", []),
            "prioritized_plan": steps,
            "suggested_commands": commands,
            "triage_report_file": triage.get("report_file"),
        }

    @mcp.tool()
    async def remote_linux_disk_cleanup(
        host: str,
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        use_sudo: bool = True,
        confirm: bool = False,
        vacuum_days: int = 7,
        clean_tmp: bool = False,
        prune_docker: bool = False,
        timeout: int = 300,
    ) -> dict:
        """Run conservative remote cleanup actions after explicit confirmation.

        Safety:
        - This modifies the remote system.
        - Set confirm=True to proceed.
        """
        if not confirm:
            return {
                "success": False,
                "error": "Refusing cleanup without explicit confirmation (confirm=True).",
            }

        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        sudo_prefix = ""
        if use_sudo:
            sudo_test = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            if sudo_test.get("success"):
                sudo_prefix = "sudo -n "

        steps = [
            ("pre_df", "df -hT"),
            ("journal_vacuum", f"{sudo_prefix}journalctl --vacuum-time={int(vacuum_days)}d || true"),
            ("force_logrotate", f"{sudo_prefix}logrotate -f /etc/logrotate.conf || true"),
            ("apt_clean", f"{sudo_prefix}apt-get clean || true"),
        ]
        if clean_tmp:
            steps.append(("tmp_cleanup", f"{sudo_prefix}find /tmp /var/tmp -mindepth 1 -delete || true"))
        if prune_docker:
            steps.append((
                "docker_prune",
                "if command -v docker >/dev/null 2>&1; then "
                f"{sudo_prefix}docker system prune -f --volumes; "
                "else echo 'docker: not installed'; fi",
            ))
        steps.append(("post_df", "df -hT"))

        raw = {}
        for name, script in steps:
            raw[name] = await _remote_exec(ssh_base, script, timeout=max(20, int(timeout // len(steps))))

        return {
            "success": True,
            "target": f"{user}@{host}:{int(ssh_port)}",
            "actions_executed": [x[0] for x in steps],
            "pre_df": raw.get("pre_df", {}).get("stdout", ""),
            "post_df": raw.get("post_df", {}).get("stdout", ""),
            "raw": raw,
        }

    @mcp.tool()
    async def remote_disk_image_create(
        host: str,
        source_device: str,
        image_path: str,
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        use_sudo: bool = True,
        hash_type: str = "sha256",
        imager: str = "dc3dd",
        timeout: int = 7200,
    ) -> dict:
        """Create a forensic disk image on a remote host.

        Supports dc3dd (preferred for integrated hashing) and ddrescue.
        """
        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        source_device = _validate_device_path(source_device)
        image_path = _validate_abs_path(image_path)
        hash_type = sanitize_arg(hash_type).lower()
        imager = sanitize_arg(imager).lower()
        if hash_type not in _VALID_HASHES:
            raise ValueError(f"Invalid hash_type: {hash_type}")
        if imager not in {"dc3dd", "ddrescue"}:
            raise ValueError("imager must be 'dc3dd' or 'ddrescue'")

        sudo_prefix = ""
        if use_sudo:
            sudo_test = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            if sudo_test.get("success"):
                sudo_prefix = "sudo -n "

        image_dir = str(Path(image_path).parent)
        log_path = f"{image_path}.{imager}.log"
        hash_path = f"{image_path}.{hash_type}"
        prep_script = f"mkdir -p {shlex.quote(image_dir)}"
        prep = await _remote_exec(ssh_base, prep_script, timeout=20)
        if not prep.get("success"):
            return prep

        if imager == "dc3dd":
            script = (
                f"{sudo_prefix}dc3dd "
                f"if={shlex.quote(source_device)} "
                f"of={shlex.quote(image_path)} "
                f"hash={shlex.quote(hash_type)} "
                f"hlog={shlex.quote(hash_path)} "
                f"log={shlex.quote(log_path)}"
            )
        else:
            map_path = f"{image_path}.ddrescue.map"
            script = (
                f"{sudo_prefix}ddrescue -f {shlex.quote(source_device)} "
                f"{shlex.quote(image_path)} {shlex.quote(map_path)} && "
                f"{sudo_prefix}{hash_type}sum {shlex.quote(image_path)} > {shlex.quote(hash_path)}"
            )

        result = await _remote_exec(ssh_base, script, timeout=timeout)
        result["artifacts"] = {
            "image_path": image_path,
            "hash_path": hash_path,
            "log_path": log_path,
        }
        return result

    @mcp.tool()
    async def attached_disk_rootcause_analysis(
        host: str,
        device: str = "/dev/sda",
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        mount_base: str = "/mnt/forensics",
        use_sudo: bool = True,
        timeout: int = 600,
    ) -> dict:
        """Analyze an attached source disk on a remote Linux host, read-only.

        Workflow:
        1) Identify device and partition type.
        2) Refuse operation if target device appears to be current OS root disk.
        3) Mount partitions read-only with filesystem-specific safe options.
        4) Run root-cause analysis (usage, top directories/files, hotspot paths).
        """
        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        device = _validate_device_path(device)
        mount_base = _validate_abs_path(mount_base)

        sudo_prefix = ""
        if use_sudo:
            sudo_test = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            if sudo_test.get("success"):
                sudo_prefix = "sudo -n "

        script = f"""
set -eu
DEVICE={shlex.quote(device)}
MOUNT_BASE={shlex.quote(mount_base)}

if [ ! -b "$DEVICE" ]; then
  echo "ERROR: Device not found: $DEVICE"
  exit 2
fi

ROOT_SRC="$(findmnt -n -o SOURCE / || true)"
ROOT_PARENT="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -n1 || true)"
if [ -n "$ROOT_PARENT" ] && [ "/dev/$ROOT_PARENT" = "$DEVICE" ]; then
  echo "ERROR: Refusing to analyze/mount current OS root disk ($DEVICE)."
  exit 3
fi

echo "=== DEVICE IDENTIFICATION ==="
{sudo_prefix}lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,LABEL,UUID,MOUNTPOINT,PKNAME "$DEVICE"
echo "=== PARTITION TABLE ==="
({sudo_prefix}parted -s "$DEVICE" print || {sudo_prefix}fdisk -l "$DEVICE") 2>/dev/null || true

PARTS="$({sudo_prefix}lsblk -ln -o NAME,TYPE "$DEVICE" | awk '$2=="part"{{print "/dev/"$1}}')"
if [ -z "$PARTS" ]; then
  echo "ERROR: No partitions found on $DEVICE"
  exit 4
fi

{sudo_prefix}mkdir -p "$MOUNT_BASE"
MOUNTED=""

for P in $PARTS; do
  FS="$({sudo_prefix}lsblk -no FSTYPE "$P" | tr -d '[:space:]')"
  MP="$MOUNT_BASE/$(basename "$P")"
  {sudo_prefix}mkdir -p "$MP"
  echo "--- Partition: $P (fstype=$FS) ---"

  if mount | awk '{{print $1}}' | grep -qx "$P"; then
    CUR="$(findmnt -n -o TARGET "$P" || true)"
    echo "Already mounted at $CUR"
    MOUNTED="$MOUNTED $CUR"
    continue
  fi

  case "$FS" in
    ext2|ext3|ext4)
      {sudo_prefix}mount -o ro,noload "$P" "$MP" || {sudo_prefix}mount -o ro "$P" "$MP"
      ;;
    xfs)
      {sudo_prefix}mount -o ro,norecovery "$P" "$MP" || {sudo_prefix}mount -o ro "$P" "$MP"
      ;;
    btrfs)
      {sudo_prefix}mount -o ro "$P" "$MP"
      ;;
    ntfs|ntfs3)
      ({sudo_prefix}mount -t ntfs3 -o ro "$P" "$MP" || {sudo_prefix}ntfs-3g -o ro "$P" "$MP") || true
      ;;
    swap|LVM2_member|crypto_LUKS)
      echo "Skipping non-direct mount partition $P ($FS)"
      continue
      ;;
    *)
      ({sudo_prefix}mount -o ro "$P" "$MP") || {{ echo "Mount failed for $P ($FS)"; continue; }}
      ;;
  esac
  MOUNTED="$MOUNTED $MP"
done

if [ -z "$MOUNTED" ]; then
  echo "ERROR: No partitions mounted read-only."
  exit 5
fi

echo "=== ROOT CAUSE ANALYSIS ==="
for MP in $MOUNTED; do
  echo "### MOUNTPOINT: $MP"
  {sudo_prefix}df -h "$MP" || true
  {sudo_prefix}df -i "$MP" || true
  echo "-- top directories --"
  {sudo_prefix}du -xhd1 "$MP" 2>/dev/null | sort -h | tail -n 30 || true
  echo "-- top files --"
  {sudo_prefix}find "$MP" -xdev -type f -printf '%s\\t%TY-%Tm-%Td %TH:%TM\\t%p\\n' 2>/dev/null | sort -nr | head -n 60 || true
  echo "-- likely hotspots --"
  for D in var/log var/lib/docker var/lib/containerd tmp var/tmp home root; do
    if [ -d "$MP/$D" ]; then
      echo "[dir] $MP/$D"
      {sudo_prefix}du -xhd1 "$MP/$D" 2>/dev/null | sort -h | tail -n 20 || true
    fi
  done
done
"""
        result = await _remote_exec(ssh_base, script, timeout=timeout)
        if result.get("stdout"):
            report_name = f"attached_disk_analysis_{sanitize_arg(host)}_{sanitize_arg(device).replace('/', '_')}.txt"
            result["report_file"] = save_output(report_name, result["stdout"])
        return result

    @mcp.tool()
    async def attached_disk_compromise_investigation(
        host: str,
        device: str = "/dev/sda",
        user: str = "root",
        ssh_port: int = 22,
        ssh_key_path: str = "",
        mount_base: str = "/mnt/forensics",
        use_sudo: bool = True,
        report_format: str = "json",
        timeout: int = 900,
    ) -> dict:
        """Perform offline compromise investigation on an attached Linux OS disk.

        Mounts disk partitions read-only on a remote analysis host, then checks for:
        - Successful SSH auth events (Accepted password/publickey)
        - Privilege escalation traces (sudo/su)
        - UID0 account anomalies
        - SSH key persistence, cron/systemd persistence
        - IOC-like suspicious files and log tamper hints

        Produces structured findings and saves a report artifact.
        """
        ssh_base = _build_ssh_base(host, user, ssh_port, ssh_key_path)
        device = _validate_device_path(device)
        mount_base = _validate_abs_path(mount_base)
        fmt = sanitize_arg(report_format).lower().strip()
        if fmt not in {"json", "markdown"}:
            return {"success": False, "error": "report_format must be 'json' or 'markdown'."}

        sudo_prefix = ""
        if use_sudo:
            sudo_test = await _remote_exec(ssh_base, "sudo -n true", timeout=10)
            if sudo_test.get("success"):
                sudo_prefix = "sudo -n "

        script = f"""
set -eu
DEVICE={shlex.quote(device)}
MOUNT_BASE={shlex.quote(mount_base)}

section() {{ echo "===SECTION:$1==="; }}

if [ ! -b "$DEVICE" ]; then
  section error
  echo "Device not found: $DEVICE"
  exit 2
fi

ROOT_SRC="$(findmnt -n -o SOURCE / || true)"
ROOT_PARENT="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -n1 || true)"
if [ -n "$ROOT_PARENT" ] && [ "/dev/$ROOT_PARENT" = "$DEVICE" ]; then
  section error
  echo "Refusing to analyze/mount current OS root disk ($DEVICE)."
  exit 3
fi

section device_info
{sudo_prefix}lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,LABEL,UUID,MOUNTPOINT,PKNAME "$DEVICE"

section partition_table
({sudo_prefix}parted -s "$DEVICE" print || {sudo_prefix}fdisk -l "$DEVICE") 2>/dev/null || true

PARTS="$({sudo_prefix}lsblk -ln -o NAME,TYPE "$DEVICE" | awk '$2=="part"{{print "/dev/"$1}}')"
if [ -z "$PARTS" ]; then
  section error
  echo "No partitions found on $DEVICE"
  exit 4
fi

{sudo_prefix}mkdir -p "$MOUNT_BASE"
MOUNTED=""
for P in $PARTS; do
  FS="$({sudo_prefix}lsblk -no FSTYPE "$P" | tr -d '[:space:]')"
  MP="$MOUNT_BASE/$(basename "$P")"
  {sudo_prefix}mkdir -p "$MP"

  if mount | awk '{{print $1}}' | grep -qx "$P"; then
    CUR="$(findmnt -n -o TARGET "$P" || true)"
    MOUNTED="$MOUNTED $CUR"
    continue
  fi

  case "$FS" in
    ext2|ext3|ext4)
      {sudo_prefix}mount -o ro,noload "$P" "$MP" || {sudo_prefix}mount -o ro "$P" "$MP" || true
      ;;
    xfs)
      {sudo_prefix}mount -o ro,norecovery "$P" "$MP" || {sudo_prefix}mount -o ro "$P" "$MP" || true
      ;;
    btrfs)
      {sudo_prefix}mount -o ro "$P" "$MP" || true
      ;;
    ntfs|ntfs3)
      ({sudo_prefix}mount -t ntfs3 -o ro "$P" "$MP" || {sudo_prefix}ntfs-3g -o ro "$P" "$MP") || true
      ;;
    swap|LVM2_member|crypto_LUKS)
      continue
      ;;
    *)
      ({sudo_prefix}mount -o ro "$P" "$MP") || true
      ;;
  esac

  if mount | awk '{{print $3}}' | grep -qx "$MP"; then
    MOUNTED="$MOUNTED $MP"
  fi
done

if [ -z "$MOUNTED" ]; then
  section error
  echo "No partitions mounted read-only."
  exit 5
fi

section mounted_points
for MP in $MOUNTED; do echo "$MP"; done

ROOT_MP=""
for MP in $MOUNTED; do
  if [ -f "$MP/etc/passwd" ] && [ -d "$MP/var/log" ]; then
    ROOT_MP="$MP"
    break
  fi
done
if [ -z "$ROOT_MP" ]; then
  ROOT_MP="$(echo "$MOUNTED" | awk '{{print $1}}')"
fi

section root_mount
echo "$ROOT_MP"

find_in_logs() {{
  PATTERN="$1"
  section_name="$2"
  section "$section_name"
  found=0
  for f in "$ROOT_MP/var/log/auth.log" "$ROOT_MP/var/log/auth.log.1" "$ROOT_MP/var/log/secure" "$ROOT_MP/var/log/messages"; do
    if [ -f "$f" ]; then
      grep -Ein "$PATTERN" "$f" | tail -n 120 || true
      found=1
    fi
  done
  for f in "$ROOT_MP"/var/log/auth.log.*.gz "$ROOT_MP"/var/log/secure-*.gz; do
    if [ -f "$f" ]; then
      zgrep -Ein "$PATTERN" "$f" | tail -n 80 || true
      found=1
    fi
  done
  if [ "$found" = 0 ]; then
    echo "No matching lines found."
  fi
}}

find_in_logs "Accepted (password|publickey)|session opened for user" "ssh_success"
find_in_logs "Failed password|Invalid user|authentication failure|Disconnected from invalid user" "ssh_failures"
find_in_logs "sudo:|su:|session opened for user root" "sudo_su_events"

section uid0_accounts
if [ -f "$ROOT_MP/etc/passwd" ]; then
  awk -F: '$3==0 {{print $0}}' "$ROOT_MP/etc/passwd" || true
else
  echo "No passwd file found."
fi

section sshd_config
if [ -f "$ROOT_MP/etc/ssh/sshd_config" ]; then
  grep -Ein '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|ChallengeResponseAuthentication|KbdInteractiveAuthentication|AllowUsers|DenyUsers)' "$ROOT_MP/etc/ssh/sshd_config" || true
else
  echo "No sshd_config found."
fi

section authorized_keys_files
found_ak=0
for d in "$ROOT_MP/root" "$ROOT_MP/home"; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      echo "--- $f ---"
      head -n 20 "$f" || true
      found_ak=1
    done < <(find "$d" -maxdepth 4 -type f -name authorized_keys 2>/dev/null)
  fi
done
[ "$found_ak" = 0 ] && echo "No authorized_keys files found."

section cron_entries
found_cron=0
for d in "$ROOT_MP/etc/cron.d" "$ROOT_MP/etc/cron.daily" "$ROOT_MP/etc/cron.hourly" "$ROOT_MP/etc/cron.weekly" "$ROOT_MP/etc/cron.monthly" "$ROOT_MP/var/spool/cron" "$ROOT_MP/var/spool/cron/crontabs"; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      echo "--- $f ---"
      sed -n '1,80p' "$f" || true
      found_cron=1
    done < <(find "$d" -maxdepth 2 -type f 2>/dev/null)
  fi
done
[ "$found_cron" = 0 ] && echo "No cron entries found."

section systemd_suspicious
found_sd=0
for d in "$ROOT_MP/etc/systemd/system" "$ROOT_MP/usr/lib/systemd/system" "$ROOT_MP/lib/systemd/system"; do
  if [ -d "$d" ]; then
    grep -RInE 'ExecStart=.*(curl|wget|bash -c|python -c|nc |ncat |socat |/tmp/|/dev/shm/)' "$d" 2>/dev/null | head -n 200 || true
    found_sd=1
  fi
done
[ "$found_sd" = 0 ] && echo "No suspicious systemd ExecStart patterns found."

section suspicious_ioc_files
found_ioc=0
for d in "$ROOT_MP/tmp" "$ROOT_MP/var/tmp" "$ROOT_MP/dev/shm" "$ROOT_MP/var/www" "$ROOT_MP/home" "$ROOT_MP/root"; do
  if [ -d "$d" ]; then
    find "$d" -xdev -type f \\( -iname '*.php' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.elf' -o -iname '*miner*' -o -iname '*kworker*' -o -iname '*xmrig*' -o -iname '.*' \\) -printf '%TY-%Tm-%Td %TH:%TM %s %p\\n' 2>/dev/null | sort -r | head -n 120 || true
    found_ioc=1
  fi
done
[ "$found_ioc" = 0 ] && echo "No obvious suspicious IOC filenames found."

section log_tamper_hints
if [ -d "$ROOT_MP/var/log" ]; then
  ls -lah "$ROOT_MP/var/log" | head -n 120 || true
  if [ ! -f "$ROOT_MP/var/log/auth.log" ] && [ ! -f "$ROOT_MP/var/log/secure" ]; then
    echo "Auth log file missing in expected paths."
  fi
else
  echo "No /var/log directory found."
fi
"""
        result = await _remote_exec(ssh_base, script, timeout=timeout)
        if not result.get("success"):
            return result

        sections = _parse_sectioned_output(result.get("stdout", ""))
        findings = _findings_from_offline_ioc_sections(sections)
        sev_weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        max_sev = max((sev_weight.get(f["severity"], 1) for f in findings), default=1)
        risk = "critical" if max_sev >= 5 else "high" if max_sev >= 4 else "medium" if max_sev >= 3 else "low"

        report_obj = {
            "success": True,
            "scan_type": "attached_disk_compromise_investigation",
            "target": f"{user}@{host}:{int(ssh_port)}",
            "device": device,
            "scan_time": format_now_tz("%Y-%m-%d %H:%M:%S %Z"),
            "risk_level": risk,
            "finding_count": len(findings),
            "findings": findings,
            "sections": sections,
        }

        slug = f"attached_compromise_{sanitize_arg(host)}_{sanitize_arg(device).replace('/', '_')}_{format_now_tz('%Y%m%d_%H%M%S')}"
        if fmt == "json":
            report_path = save_output(f"{slug}.json", json.dumps(report_obj, indent=2))
        else:
            lines = [
                "# Attached Disk Compromise Investigation Report",
                "",
                f"- Target: `{user}@{host}:{int(ssh_port)}`",
                f"- Device: `{device}`",
                f"- Time: {report_obj['scan_time']}",
                f"- Risk Level: **{risk.upper()}**",
                f"- Findings: **{len(findings)}**",
                "",
                "## Findings",
                "",
            ]
            for i, f in enumerate(findings, 1):
                lines.extend([
                    f"### {i}. [{f['severity'].upper()}] {f['title']}",
                    "",
                    f.get("description", ""),
                    "",
                    "**Evidence:**",
                    "```",
                    (f.get("evidence", "") or "")[:3000],
                    "```",
                    "",
                    f"**Recommendation:** {f.get('recommendation', '')}",
                    "",
                    "---",
                    "",
                ])
            report_path = save_output(f"{slug}.md", "\n".join(lines))

        report_obj["report_file"] = report_path
        return report_obj
