#!/usr/bin/env python3
"""Generate a .env file with secure dashboard defaults."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import secrets
from pathlib import Path


def _build_password_hash(password: str, iterations: int) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a dashboard .env file with secure defaults"
    )
    parser.add_argument(
        "--output",
        default=".env.dashboard",
        help="Output env file path (default: .env.dashboard)",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Dashboard username (default: admin)",
    )
    parser.add_argument(
        "--password",
        default="",
        help="Dashboard password (omit to prompt securely)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200000,
        help="PBKDF2 iterations for password hash (default: 200000)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output file if it already exists",
    )
    args = parser.parse_args()

    out_path = Path(args.output)
    if out_path.exists() and not args.overwrite:
        raise SystemExit(
            f"Refusing to overwrite existing file: {out_path}. Use --overwrite to replace it."
        )

    password = args.password or getpass.getpass("Dashboard password: ")
    if not password:
        raise SystemExit("Password cannot be empty")

    iterations = max(10000, int(args.iterations))
    password_hash = _build_password_hash(password, iterations)
    token = secrets.token_urlsafe(32)

    env_lines = [
        "# Auto-generated dashboard security settings",
        "MCP_DASHBOARD_ENABLED=true",
        "MCP_DASHBOARD_HOST=0.0.0.0",
        "MCP_DASHBOARD_PORT=8090",
        "",
        "# Dashboard auth (token + login)",
        f"MCP_DASHBOARD_AUTH_TOKEN={token}",
        f"MCP_DASHBOARD_USERNAME={args.username}",
        f"MCP_DASHBOARD_PASSWORD_HASH={password_hash}",
        "MCP_DASHBOARD_PASSWORD=",
        "",
        "# Login abuse protections",
        "MCP_DASHBOARD_LOGIN_MAX_ATTEMPTS=5",
        "MCP_DASHBOARD_LOGIN_WINDOW_SECONDS=300",
        "MCP_DASHBOARD_LOGIN_LOCKOUT_SECONDS=900",
        "",
        "# Set to true if dashboard served via HTTPS",
        "MCP_DASHBOARD_COOKIE_SECURE=false",
        "",
    ]

    out_path.write_text("\n".join(env_lines), encoding="utf-8")
    print(f"Wrote dashboard env file: {out_path}")
    print("Generated values:")
    print("- MCP_DASHBOARD_AUTH_TOKEN (random)")
    print("- MCP_DASHBOARD_PASSWORD_HASH (PBKDF2-SHA256)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
