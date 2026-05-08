#!/usr/bin/env python3
"""Generate a signed subscription license file."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _sign_payload(private_key: Any, payload: dict[str, Any]) -> str:
    data = _canonical_payload_bytes(payload)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(data)
    elif isinstance(private_key, ed448.Ed448PrivateKey):
        signature = private_key.sign(data)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported private key type. Use Ed25519/Ed448/RSA/EC PEM keys.")
    return base64.b64encode(signature).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate signed subscription.lic from a private key")
    parser.add_argument("--subscriber-name", required=True, help="Subscriber or customer display name")
    parser.add_argument("--start-date", required=True, help="Subscription start date (YYYY-MM-DD or ISO-8601)")
    parser.add_argument("--end-date", required=True, help="Subscription end date (YYYY-MM-DD or ISO-8601)")
    parser.add_argument("--private-key", required=True, help="Path to PEM private key used for signing")
    parser.add_argument("--output", default="subscription.lic", help="Output license file path")
    parser.add_argument("--issuer-id", default="unified-threatlens", help="Issuer identifier")
    parser.add_argument("--key-id", default="vendor-default-2026", help="Issuer key identifier")
    parser.add_argument(
        "--issued-at",
        default="",
        help="Optional issue timestamp (ISO-8601). Default: current UTC timestamp",
    )
    args = parser.parse_args()

    issued_at = args.issued_at.strip() or datetime.now(timezone.utc).isoformat()
    payload = {
        "subscriber_name": args.subscriber_name.strip(),
        "subscription_start_date": args.start_date.strip(),
        "subscription_end_date": args.end_date.strip(),
        "issued_at": issued_at,
        "issuer_id": args.issuer_id.strip(),
        "key_id": args.key_id.strip(),
    }
    if not payload["subscriber_name"]:
        raise SystemExit("subscriber-name cannot be empty")
    if not payload["issuer_id"] or not payload["key_id"]:
        raise SystemExit("issuer-id and key-id cannot be empty")

    private_key = _load_private_key(Path(args.private_key))
    license_doc = {
        "payload": payload,
        "signature": _sign_payload(private_key, payload),
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(license_doc, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

