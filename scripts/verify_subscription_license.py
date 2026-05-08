#!/usr/bin/env python3
"""Verify a signed subscription license file using a public key."""

from __future__ import annotations

import argparse
import json
import os

from tools.subscription import get_subscription_status


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify subscription.lic and print status JSON")
    parser.add_argument("--license-path", required=True, help="Path to subscription.lic")
    parser.add_argument(
        "--public-key-path",
        default="",
        help="Optional override path to PEM public key (development mode only)",
    )
    parser.add_argument(
        "--trust-mode",
        default="prod",
        choices=["prod", "dev"],
        help="Subscription trust mode (default: prod)",
    )
    parser.add_argument(
        "--allow-key-override",
        action="store_true",
        help="Allow key override in development mode",
    )
    args = parser.parse_args()

    os.environ["MCP_SUBSCRIPTION_LICENSE_PATH"] = args.license_path
    os.environ["MCP_SUBSCRIPTION_TRUST_MODE"] = args.trust_mode
    os.environ["MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE"] = "true" if args.allow_key_override else "false"
    if args.public_key_path:
        os.environ["MCP_SUBSCRIPTION_PUBLIC_KEY_PATH"] = args.public_key_path

    status = get_subscription_status(force_refresh=True)
    print(json.dumps(status, ensure_ascii=True, indent=2))
    return 0 if status.get("active") else 1


if __name__ == "__main__":
    raise SystemExit(main())

