#!/usr/bin/env python3
"""Post-Quantum Cryptography (PQC) scanner.

Probes a TLS server to detect PQC / hybrid key-exchange support,
analyses certificate signature algorithms for quantum-resistance,
and checks TLS 1.3 group advertisements.

Usage:
    python3 pqc_scanner.py <host> [port] [--json]
"""

import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import os
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo

PQC_KEX_GROUPS = {
    "x25519_kyber768":    {"id": 0x6399, "type": "hybrid",  "nist_level": 3},
    "x25519_kyber512":    {"id": 0x639A, "type": "hybrid",  "nist_level": 1},
    "x448_kyber768":      {"id": 0x639B, "type": "hybrid",  "nist_level": 3},
    "p256_kyber512":      {"id": 0x639C, "type": "hybrid",  "nist_level": 1},
    "p384_kyber768":      {"id": 0x639D, "type": "hybrid",  "nist_level": 3},
    "p521_kyber1024":     {"id": 0x639E, "type": "hybrid",  "nist_level": 5},
    "kyber512":           {"id": 0x023A, "type": "pure_pqc", "nist_level": 1},
    "kyber768":           {"id": 0x023C, "type": "pure_pqc", "nist_level": 3},
    "kyber1024":          {"id": 0x023D, "type": "pure_pqc", "nist_level": 5},
    "mlkem512":           {"id": 0x0200, "type": "pure_pqc", "nist_level": 1},
    "mlkem768":           {"id": 0x0201, "type": "pure_pqc", "nist_level": 3},
    "mlkem1024":          {"id": 0x0202, "type": "pure_pqc", "nist_level": 5},
    "x25519_mlkem768":    {"id": 0x11EC, "type": "hybrid",  "nist_level": 3},
    "secp256r1_mlkem768": {"id": 0x11EB, "type": "hybrid",  "nist_level": 3},
    "secp384r1_mlkem1024":{"id": 0x11ED, "type": "hybrid",  "nist_level": 5},
}

PQC_SIG_ALGORITHMS = {
    "dilithium2":        {"nist_level": 2, "standard": "ML-DSA-44"},
    "dilithium3":        {"nist_level": 3, "standard": "ML-DSA-65"},
    "dilithium5":        {"nist_level": 5, "standard": "ML-DSA-87"},
    "mldsa44":           {"nist_level": 2, "standard": "ML-DSA-44"},
    "mldsa65":           {"nist_level": 3, "standard": "ML-DSA-65"},
    "mldsa87":           {"nist_level": 5, "standard": "ML-DSA-87"},
    "falcon512":         {"nist_level": 1, "standard": "FN-DSA-512"},
    "falcon1024":        {"nist_level": 5, "standard": "FN-DSA-1024"},
    "sphincssha2128fsimple": {"nist_level": 1, "standard": "SLH-DSA-SHA2-128f"},
    "sphincssha2128ssimple": {"nist_level": 1, "standard": "SLH-DSA-SHA2-128s"},
    "sphincssha2192fsimple": {"nist_level": 3, "standard": "SLH-DSA-SHA2-192f"},
    "sphincssha2256fsimple": {"nist_level": 5, "standard": "SLH-DSA-SHA2-256f"},
}

QUANTUM_VULNERABLE_ALGORITHMS = {
    "rsa":         "Vulnerable to Shor's algorithm",
    "ecdsa":       "Vulnerable to Shor's algorithm on elliptic curves",
    "ed25519":     "Vulnerable to Shor's algorithm",
    "ed448":       "Vulnerable to Shor's algorithm",
    "dsa":         "Vulnerable to Shor's algorithm",
    "dh":          "Vulnerable to Shor's algorithm",
    "ecdh":        "Vulnerable to Shor's algorithm on elliptic curves",
}


def _configured_timezone() -> tzinfo:
    raw = (
        os.environ.get("TIMEZONE", "").strip()
        or os.environ.get("TZ", "").strip()
        or "Asia/Kuala_Lumpur"
    )
    try:
        return ZoneInfo(raw)
    except Exception:
        return timezone(timedelta(hours=8), name="Asia/Kuala_Lumpur")


def _now_iso_tz() -> str:
    return datetime.now(_configured_timezone()).isoformat()


def probe_tls13_groups(host: str, port: int) -> dict:
    """Connect via TLS 1.3 and extract the negotiated key-exchange group."""
    result = {"tls13_supported": False, "negotiated_group": None, "pqc_group": False}
    try:
        r = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-tls1_3", "-brief"],
            input=b"", capture_output=True, timeout=15,
        )
        output = (r.stdout + r.stderr).decode("utf-8", errors="replace")
        if "Protocol version: TLSv1.3" in output or "TLSv1.3" in output:
            result["tls13_supported"] = True
        group_match = re.search(r"Server Temp Key:\s*(.+)", output)
        if group_match:
            result["negotiated_group"] = group_match.group(1).strip()
        for pqc_name in PQC_KEX_GROUPS:
            if pqc_name.lower() in output.lower():
                result["pqc_group"] = True
                result["negotiated_group"] = pqc_name
                break
    except Exception as e:
        result["error"] = str(e)
    return result


def probe_pqc_groups(host: str, port: int) -> dict:
    """Try each known PQC group with openssl s_client -groups to see if server accepts it."""
    supported = []
    unsupported = []
    groups_to_try = [
        "x25519_kyber768", "X25519Kyber768Draft00", "x25519_mlkem768",
        "secp256r1_mlkem768", "secp384r1_mlkem1024",
        "kyber512", "kyber768", "kyber1024",
        "mlkem512", "mlkem768", "mlkem1024",
    ]
    for group in groups_to_try:
        try:
            r = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-tls1_3", "-groups", group],
                input=b"", capture_output=True, timeout=10,
            )
            output = (r.stdout + r.stderr).decode("utf-8", errors="replace")
            if "Server Temp Key" in output and "error" not in output.lower():
                supported.append(group)
            else:
                unsupported.append(group)
        except Exception:
            unsupported.append(group)
    return {"supported": supported, "unsupported": unsupported}


def get_cert_info(host: str, port: int) -> dict:
    """Retrieve certificate details and assess quantum-vulnerability of its signature."""
    result = {
        "subject": None,
        "issuer": None,
        "sig_algorithm": None,
        "public_key_type": None,
        "public_key_bits": None,
        "not_before": None,
        "not_after": None,
        "quantum_vulnerable": True,
        "pqc_signature": False,
        "vulnerabilities": [],
        "recommendations": [],
    }
    try:
        r = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host],
            input=b"", capture_output=True, timeout=15,
        )
        cert_pem = (r.stdout).decode("utf-8", errors="replace")

        r2 = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=cert_pem.encode(), capture_output=True, timeout=10,
        )
        cert_text = r2.stdout.decode("utf-8", errors="replace")

        sig_match = re.search(r"Signature Algorithm:\s*(\S+)", cert_text)
        if sig_match:
            result["sig_algorithm"] = sig_match.group(1)

        pk_match = re.search(r"Public Key Algorithm:\s*(\S+)", cert_text)
        if pk_match:
            result["public_key_type"] = pk_match.group(1)

        bits_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)
        if bits_match:
            result["public_key_bits"] = int(bits_match.group(1))

        subj_match = re.search(r"Subject:\s*(.+)", cert_text)
        if subj_match:
            result["subject"] = subj_match.group(1).strip()

        iss_match = re.search(r"Issuer:\s*(.+)", cert_text)
        if iss_match:
            result["issuer"] = iss_match.group(1).strip()

        nb_match = re.search(r"Not Before:\s*(.+)", cert_text)
        if nb_match:
            result["not_before"] = nb_match.group(1).strip()

        na_match = re.search(r"Not After\s*:\s*(.+)", cert_text)
        if na_match:
            result["not_after"] = na_match.group(1).strip()

        sig_alg = (result["sig_algorithm"] or "").lower()
        pk_type = (result["public_key_type"] or "").lower()

        for pqc_sig_name in PQC_SIG_ALGORITHMS:
            if pqc_sig_name in sig_alg or pqc_sig_name in pk_type:
                result["pqc_signature"] = True
                result["quantum_vulnerable"] = False
                break

        if result["quantum_vulnerable"]:
            for vuln_alg, reason in QUANTUM_VULNERABLE_ALGORITHMS.items():
                if vuln_alg in sig_alg or vuln_alg in pk_type:
                    result["vulnerabilities"].append({
                        "algorithm": vuln_alg,
                        "reason": reason,
                        "severity": "high" if result.get("public_key_bits", 0) < 3072 else "medium",
                    })

            result["recommendations"].append(
                "Migrate to PQC or hybrid certificates (ML-DSA / Dilithium recommended by NIST)"
            )
            if result.get("public_key_bits") and result["public_key_bits"] < 3072:
                result["recommendations"].append(
                    f"Current key size ({result['public_key_bits']} bits) is below NIST minimum "
                    "for near-term quantum resistance. Use at least 3072-bit RSA or migrate to PQC."
                )

    except Exception as e:
        result["error"] = str(e)
    return result


def check_testssl_pqc(host: str, port: int) -> dict:
    """Use testssl.sh to detect PQC-related findings."""
    result = {"raw": "", "pqc_findings": []}
    try:
        r = subprocess.run(
            ["testssl", "--color", "0", "--protocols", "--server-preference",
             "--server-defaults", f"{host}:{port}"],
            capture_output=True, timeout=120,
        )
        output = r.stdout.decode("utf-8", errors="replace")
        result["raw"] = output
        pqc_keywords = [
            "kyber", "mlkem", "ml-kem", "dilithium", "mldsa", "ml-dsa",
            "falcon", "sphincs", "slh-dsa", "post-quantum", "hybrid",
            "x25519kyber", "x25519_kyber", "x25519_mlkem",
        ]
        for line in output.split("\n"):
            for kw in pqc_keywords:
                if kw in line.lower():
                    result["pqc_findings"].append(line.strip())
                    break
    except Exception as e:
        result["error"] = str(e)
    return result


def generate_pqc_assessment(host: str, port: int) -> dict:
    """Full PQC readiness assessment combining all probes."""
    assessment = {
        "target": f"{host}:{port}",
        "scan_time": _now_iso_tz(),
        "tls_info": probe_tls13_groups(host, port),
        "pqc_groups": probe_pqc_groups(host, port),
        "certificate": get_cert_info(host, port),
        "testssl_pqc": check_testssl_pqc(host, port),
    }

    score = 0
    max_score = 100
    details = []

    if assessment["tls_info"]["tls13_supported"]:
        score += 20
        details.append("[PASS] TLS 1.3 supported (prerequisite for PQC key exchange)")
    else:
        details.append("[FAIL] TLS 1.3 not supported — PQC key exchange requires TLS 1.3")

    pqc_groups = assessment["pqc_groups"]["supported"]
    if pqc_groups:
        score += 40
        details.append(f"[PASS] PQC key exchange groups supported: {', '.join(pqc_groups)}")
        hybrid_groups = [g for g in pqc_groups if "x25519" in g.lower() or "secp" in g.lower()]
        if hybrid_groups:
            score += 10
            details.append(f"[PASS] Hybrid PQC groups detected: {', '.join(hybrid_groups)}")
    else:
        details.append("[FAIL] No PQC key exchange groups supported")

    cert = assessment["certificate"]
    if cert.get("pqc_signature"):
        score += 30
        details.append("[PASS] Certificate uses PQC signature algorithm")
    else:
        sig = cert.get("sig_algorithm", "unknown")
        pk = cert.get("public_key_type", "unknown")
        bits = cert.get("public_key_bits", 0)
        details.append(f"[WARN] Certificate uses classical signature: {sig} ({pk}, {bits} bits)")
        if bits and bits >= 3072:
            score += 5
            details.append(f"[INFO] Key size ({bits} bits) meets minimum for near-term protection")

    if score >= 70:
        readiness = "HIGH"
        summary = "Server demonstrates strong PQC readiness with hybrid or pure PQC support."
    elif score >= 40:
        readiness = "MODERATE"
        summary = "Server has partial PQC readiness. TLS 1.3 present but key exchange or certificates need PQC migration."
    elif score >= 20:
        readiness = "LOW"
        summary = "Server supports TLS 1.3 but lacks PQC key exchange and certificate support."
    else:
        readiness = "NONE"
        summary = "Server has no PQC readiness. Immediate migration planning recommended."

    assessment["pqc_readiness"] = {
        "score": score,
        "max_score": max_score,
        "readiness_level": readiness,
        "summary": summary,
        "details": details,
        "recommendations": cert.get("recommendations", []) + [
            "Enable TLS 1.3 with X25519Kyber768 hybrid key exchange",
            "Plan migration to ML-DSA (Dilithium) certificates when CA support is available",
            "Test with browsers that support PQC (Chrome 116+, Firefox Nightly)",
            "Monitor NIST PQC standardisation updates at https://csrc.nist.gov/projects/post-quantum-cryptography",
        ],
    }

    return assessment


def main():
    if len(sys.argv) < 2:
        print("Usage: pqc_scanner.py <host> [port] [--json]", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 443
    use_json = "--json" in sys.argv

    result = generate_pqc_assessment(host, port)

    if use_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"{'='*72}")
        print(f"  Post-Quantum Cryptography Readiness Assessment")
        print(f"  Target: {host}:{port}")
        print(f"  Time:   {result['scan_time']}")
        print(f"{'='*72}\n")

        rd = result["pqc_readiness"]
        print(f"  READINESS SCORE: {rd['score']}/{rd['max_score']}  ({rd['readiness_level']})")
        print(f"  {rd['summary']}\n")

        print("  Detailed Findings:")
        print("  " + "-" * 60)
        for d in rd["details"]:
            print(f"    {d}")

        print(f"\n  Certificate Info:")
        print("  " + "-" * 60)
        cert = result["certificate"]
        print(f"    Subject:    {cert.get('subject', 'N/A')}")
        print(f"    Issuer:     {cert.get('issuer', 'N/A')}")
        print(f"    Signature:  {cert.get('sig_algorithm', 'N/A')}")
        print(f"    Key Type:   {cert.get('public_key_type', 'N/A')} ({cert.get('public_key_bits', '?')} bits)")
        print(f"    Valid:      {cert.get('not_before', '?')} — {cert.get('not_after', '?')}")
        print(f"    PQC Sig:    {'Yes' if cert.get('pqc_signature') else 'No'}")
        if cert.get("vulnerabilities"):
            print(f"    Quantum Vulnerabilities:")
            for v in cert["vulnerabilities"]:
                print(f"      - [{v['severity'].upper()}] {v['algorithm']}: {v['reason']}")

        pqc_grp = result["pqc_groups"]
        print(f"\n  PQC Key Exchange Groups:")
        print("  " + "-" * 60)
        if pqc_grp["supported"]:
            for g in pqc_grp["supported"]:
                print(f"    [SUPPORTED] {g}")
        else:
            print(f"    No PQC groups supported")

        testssl = result.get("testssl_pqc", {})
        if testssl.get("pqc_findings"):
            print(f"\n  testssl.sh PQC Findings:")
            print("  " + "-" * 60)
            for f in testssl["pqc_findings"]:
                print(f"    {f}")

        print(f"\n  Recommendations:")
        print("  " + "-" * 60)
        for r in rd["recommendations"]:
            print(f"    • {r}")
        print(f"\n{'='*72}")


if __name__ == "__main__":
    main()
