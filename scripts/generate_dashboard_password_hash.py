#!/usr/bin/env python3
"""Generate a dashboard password hash for MCP_DASHBOARD_PASSWORD_HASH.

Output format:
  pbkdf2_sha256$<iterations>$<salt>$<hex_digest>
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate PBKDF2-SHA256 hash for dashboard login password"
    )
    parser.add_argument(
        "--password",
        default="",
        help="Password to hash (omit to be prompted securely)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200000,
        help="PBKDF2 iterations (default: 200000)",
    )
    parser.add_argument(
        "--salt",
        default="",
        help="Optional custom salt (default: random hex)",
    )
    args = parser.parse_args()

    iterations = max(10000, int(args.iterations))
    password = args.password or getpass.getpass("Dashboard password: ")
    if not password:
        raise SystemExit("Password cannot be empty")

    salt = args.salt or os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    print(f"pbkdf2_sha256${iterations}${salt}${digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
