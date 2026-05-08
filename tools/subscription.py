"""Subscription license verification and status helpers."""

from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from tools.audit_logger import write_audit_event
from tools.time_utils import configured_timezone, now_tz

_DEFAULT_LICENSE_PATH = "/opt/uts-mcp/data/subscription.lic"
_DEFAULT_WARNING_DAYS = 14
_MAX_LICENSE_SIZE_BYTES = 128 * 1024
_REQUIRED_LICENSE_KEYS = {"payload", "signature"}
_REQUIRED_PAYLOAD_KEYS = {
    "subscriber_name",
    "subscription_start_date",
    "subscription_end_date",
    "issued_at",
}
_OPTIONAL_PAYLOAD_KEYS = {"issuer_id", "key_id"}
_DEFAULT_TRUST_MODE = "prod"
_DEFAULT_ALLOW_KEY_OVERRIDE = False
_DEFAULT_LEGACY_COMPAT = True
_DEFAULT_PINNED_KEYRING_PATH = "/opt/uts-mcp/config/subscription-keys/keys.json"
_DEFAULT_PINNED_PUBLIC_KEY_PATH = "/opt/uts-mcp/config/subscription-public.pem"

_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {
    "mtime_ns": None,
    "status": None,
}
_OVERRIDE_AUDIT_ONCE_LOCK = threading.Lock()
_OVERRIDE_AUDIT_EMITTED = False


def subscription_license_path() -> Path:
    raw = os.environ.get("MCP_SUBSCRIPTION_LICENSE_PATH", "").strip()
    return Path(raw or _DEFAULT_LICENSE_PATH)


def subscription_warning_days() -> int:
    raw = os.environ.get("MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS", str(_DEFAULT_WARNING_DAYS)).strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_WARNING_DAYS


def subscription_trust_mode() -> str:
    raw = os.environ.get("MCP_SUBSCRIPTION_TRUST_MODE", _DEFAULT_TRUST_MODE).strip().lower()
    if raw not in {"prod", "dev"}:
        return _DEFAULT_TRUST_MODE
    return raw


def subscription_allow_key_override() -> bool:
    raw = os.environ.get("MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE", str(_DEFAULT_ALLOW_KEY_OVERRIDE)).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def subscription_legacy_compat_enabled() -> bool:
    raw = os.environ.get("MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT", str(_DEFAULT_LEGACY_COMPAT)).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def subscription_keyring_path() -> Path:
    raw = os.environ.get("MCP_SUBSCRIPTION_KEYRING_PATH", "").strip()
    return Path(raw or _DEFAULT_PINNED_KEYRING_PATH)


def subscription_pinned_public_key_path() -> Path:
    raw = os.environ.get("MCP_SUBSCRIPTION_PINNED_PUBLIC_KEY_PATH", "").strip()
    return Path(raw or _DEFAULT_PINNED_PUBLIC_KEY_PATH)


def _override_material_present() -> bool:
    return bool(
        os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PEM", "").strip()
        or os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PATH", "").strip()
    )


def _is_override_active() -> bool:
    return (
        subscription_trust_mode() == "dev"
        and subscription_allow_key_override()
        and _override_material_present()
    )


def _emit_override_audit_once() -> None:
    global _OVERRIDE_AUDIT_EMITTED
    if not _is_override_active():
        return
    with _OVERRIDE_AUDIT_ONCE_LOCK:
        if _OVERRIDE_AUDIT_EMITTED:
            return
        write_audit_event(
            "subscription.override_mode",
            {
                "message": "Subscription verification key override is active (development mode).",
                "trust_mode": subscription_trust_mode(),
                "allow_key_override": subscription_allow_key_override(),
            },
        )
        _OVERRIDE_AUDIT_EMITTED = True


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_iso_datetime(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=configured_timezone())
    return dt.astimezone(configured_timezone())


def _parse_license_date(value: str, *, end_of_day: bool) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    # If only a date is provided, interpret in configured local timezone.
    if len(raw) == 10 and raw.count("-") == 2:
        try:
            parsed_date = datetime.strptime(raw, "%Y-%m-%d").date()
        except ValueError:
            return None
        boundary = time(23, 59, 59) if end_of_day else time(0, 0, 0)
        return datetime.combine(parsed_date, boundary, tzinfo=configured_timezone())
    return _parse_iso_datetime(raw)


def _load_public_key_from_pem_bytes(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def _public_key_fingerprint_sha256(public_key: Any) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return base64.b64encode(digest.finalize()).decode("ascii")


def _verify_fingerprint(public_key: Any, expected_fingerprint: str) -> bool:
    expected = str(expected_fingerprint or "").strip()
    if not expected:
        return False
    actual = _public_key_fingerprint_sha256(public_key)
    return actual == expected


def _normalize_keyring_document(raw_doc: Any) -> list[dict[str, Any]]:
    if isinstance(raw_doc, list):
        rows = raw_doc
    elif isinstance(raw_doc, dict):
        rows = raw_doc.get("keys", [])
    else:
        raise ValueError("Keyring must be a list or object with a 'keys' list.")
    if not isinstance(rows, list):
        raise ValueError("Keyring 'keys' value must be a list.")
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each keyring entry must be an object.")
        issuer_id = str(row.get("issuer_id", "")).strip()
        key_id = str(row.get("key_id", "")).strip()
        key_path = str(row.get("public_key_path", "")).strip()
        fingerprint = str(row.get("fingerprint_sha256", "")).strip()
        if not issuer_id or not key_id or not key_path or not fingerprint:
            raise ValueError("Each keyring entry requires issuer_id, key_id, public_key_path, fingerprint_sha256.")
        normalized.append(
            {
                "issuer_id": issuer_id,
                "key_id": key_id,
                "public_key_path": key_path,
                "fingerprint_sha256": fingerprint,
            }
        )
    return normalized


def _load_keyring_entries() -> list[dict[str, Any]]:
    keyring_path = subscription_keyring_path()
    if not keyring_path.exists():
        return []
    raw = json.loads(keyring_path.read_text(encoding="utf-8"))
    entries = _normalize_keyring_document(raw)
    resolved: list[dict[str, Any]] = []
    for entry in entries:
        path_value = Path(entry["public_key_path"])
        if not path_value.is_absolute():
            path_value = (keyring_path.parent / path_value).resolve()
        pem_bytes = path_value.read_bytes()
        public_key = _load_public_key_from_pem_bytes(pem_bytes)
        if not _verify_fingerprint(public_key, entry["fingerprint_sha256"]):
            raise ValueError(f"Fingerprint mismatch for keyring entry {entry['issuer_id']}:{entry['key_id']}.")
        resolved.append(
            {
                "issuer_id": entry["issuer_id"],
                "key_id": entry["key_id"],
                "public_key": public_key,
                "fingerprint_sha256": entry["fingerprint_sha256"],
                "source": "keyring",
            }
        )
    return resolved


def _load_override_public_key() -> tuple[Any | None, str, str]:
    inline_pem = os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PEM", "").strip()
    key_path = os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PATH", "").strip()
    if inline_pem:
        pem_bytes = inline_pem.replace("\\n", "\n").encode("utf-8")
        return _load_public_key_from_pem_bytes(pem_bytes), "", ""
    if key_path:
        pem_bytes = Path(key_path).read_bytes()
        return _load_public_key_from_pem_bytes(pem_bytes), "", ""
    return None, "subscription_public_key_missing", "Subscription override key is not configured."


def _load_single_pinned_key() -> tuple[dict[str, Any] | None, str, str]:
    path = subscription_pinned_public_key_path()
    if not path.exists():
        return None, "subscription_public_key_missing", "Pinned subscription public key is not configured."
    public_key = _load_public_key_from_pem_bytes(path.read_bytes())
    expected_fingerprint = str(os.environ.get("MCP_SUBSCRIPTION_PINNED_KEY_FINGERPRINT_SHA256", "")).strip()
    if expected_fingerprint and not _verify_fingerprint(public_key, expected_fingerprint):
        return None, "subscription_fingerprint_mismatch", "Pinned subscription key fingerprint mismatch."
    return (
        {
            "issuer_id": "legacy",
            "key_id": "legacy",
            "public_key": public_key,
            "fingerprint_sha256": _public_key_fingerprint_sha256(public_key),
            "source": "pinned_single",
        },
        "",
        "",
    )


def _verify_signature(public_key: Any, payload: dict[str, Any], signature_b64: str) -> bool:
    data = _canonical_payload_bytes(payload)
    signature = base64.b64decode(str(signature_b64 or "").encode("utf-8"), validate=True)
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, ed448.Ed448PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _base_status(state: str, code: str, message: str) -> dict[str, Any]:
    return {
        "active": state == "active",
        "state": state,
        "code": code,
        "message": message,
        "checked_at": now_tz().isoformat(),
        "license_path": str(subscription_license_path()),
        "subscriber_name": "",
        "subscription_start_date": "",
        "subscription_end_date": "",
        "issued_at": "",
        "issuer_id": "",
        "key_id": "",
        "key_source": "",
        "key_fingerprint_sha256": "",
        "trust_mode": subscription_trust_mode(),
        "key_override_active": _is_override_active(),
        "legacy_compat_enabled": subscription_legacy_compat_enabled(),
        "expires_in_days": None,
        "expiring_soon": False,
    }


def _validate_license_schema(license_doc: dict[str, Any]) -> tuple[bool, str, str]:
    keys = set(license_doc.keys())
    unknown_top = sorted(keys - _REQUIRED_LICENSE_KEYS)
    missing_top = sorted(_REQUIRED_LICENSE_KEYS - keys)
    if missing_top or unknown_top:
        return (
            False,
            "subscription_invalid_schema",
            "Subscription schema is invalid: top-level fields must be exactly payload and signature.",
        )

    payload = license_doc.get("payload")
    signature = license_doc.get("signature")
    if not isinstance(payload, dict):
        return (
            False,
            "subscription_invalid_schema",
            "Subscription schema is invalid: payload must be an object.",
        )
    if not isinstance(signature, str) or not signature.strip():
        return (
            False,
            "subscription_invalid_schema",
            "Subscription schema is invalid: signature must be a non-empty string.",
        )

    allowed_payload = set(_REQUIRED_PAYLOAD_KEYS) | set(_OPTIONAL_PAYLOAD_KEYS)
    payload_keys = set(payload.keys())
    unknown_payload = sorted(payload_keys - allowed_payload)
    missing_payload = sorted(_REQUIRED_PAYLOAD_KEYS - payload_keys)
    if missing_payload or unknown_payload:
        return (
            False,
            "subscription_invalid_schema",
            (
                "Subscription schema is invalid: payload fields must include "
                "subscriber_name, subscription_start_date, subscription_end_date, issued_at "
                "and may optionally include issuer_id, key_id."
            ),
        )

    for key in _REQUIRED_PAYLOAD_KEYS:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            return (
                False,
                "subscription_invalid_schema",
                f"Subscription schema is invalid: {key} must be a non-empty string.",
            )

    issuer_id = payload.get("issuer_id")
    key_id = payload.get("key_id")
    if issuer_id is not None and (not isinstance(issuer_id, str) or not issuer_id.strip()):
        return False, "subscription_invalid_schema", "Subscription schema is invalid: issuer_id must be a non-empty string."
    if key_id is not None and (not isinstance(key_id, str) or not key_id.strip()):
        return False, "subscription_invalid_schema", "Subscription schema is invalid: key_id must be a non-empty string."
    if (issuer_id is None) ^ (key_id is None):
        return False, "subscription_invalid_schema", "Subscription schema is invalid: issuer_id and key_id must be provided together."
    if not subscription_legacy_compat_enabled() and (issuer_id is None or key_id is None):
        return False, "subscription_invalid_schema", "Subscription schema is invalid: issuer_id and key_id are required."

    return True, "", ""


def _resolve_verification_key(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str, str]:
    issuer_id = str(payload.get("issuer_id", "")).strip()
    key_id = str(payload.get("key_id", "")).strip()

    if _is_override_active():
        _emit_override_audit_once()
        override_key, code, message = _load_override_public_key()
        if override_key is None:
            return None, code, message
        return (
            {
                "issuer_id": issuer_id,
                "key_id": key_id,
                "public_key": override_key,
                "fingerprint_sha256": _public_key_fingerprint_sha256(override_key),
                "source": "override",
            },
            "",
            "",
        )

    keyring_entries = _load_keyring_entries()
    if keyring_entries:
        if issuer_id and key_id:
            for entry in keyring_entries:
                if entry["issuer_id"] == issuer_id and entry["key_id"] == key_id:
                    return entry, "", ""
            return None, "subscription_unknown_issuer_key", "Subscription issuer/key is not trusted."
        if not subscription_legacy_compat_enabled():
            return None, "subscription_unknown_issuer_key", "Subscription issuer/key is required."
        if len(keyring_entries) == 1:
            return keyring_entries[0], "", ""
        return None, "subscription_unknown_issuer_key", "Subscription issuer/key is required when multiple keys are pinned."

    pinned, code, message = _load_single_pinned_key()
    if pinned is None:
        return None, code, message
    return pinned, "", ""


def _evaluate_license_document(license_doc: dict[str, Any]) -> dict[str, Any]:
    is_valid_schema, schema_code, schema_message = _validate_license_schema(license_doc)
    if not is_valid_schema:
        return _base_status("invalid", schema_code, schema_message)

    payload = license_doc.get("payload")
    signature = str(license_doc.get("signature", "")).strip()
    key_meta, key_code, key_message = _resolve_verification_key(payload)
    if key_meta is None:
        return _base_status("invalid", key_code, key_message)
    if not _verify_signature(key_meta["public_key"], payload, signature):
        return _base_status(
            "invalid",
            "subscription_invalid_signature",
            "Subscription signature verification failed.",
        )

    subscriber_name = str(payload.get("subscriber_name", "")).strip()
    start_raw = str(payload.get("subscription_start_date", "")).strip()
    end_raw = str(payload.get("subscription_end_date", "")).strip()
    issued_at = str(payload.get("issued_at", "")).strip()
    issuer_id = str(payload.get("issuer_id", "")).strip() or str(key_meta.get("issuer_id", "")).strip()
    key_id = str(payload.get("key_id", "")).strip() or str(key_meta.get("key_id", "")).strip()

    issued_dt = _parse_iso_datetime(issued_at)
    if issued_dt is None:
        return _base_status(
            "invalid",
            "subscription_invalid_dates",
            "Subscription issued_at must be a valid ISO-8601 timestamp.",
        )

    start_dt = _parse_license_date(start_raw, end_of_day=False)
    end_dt = _parse_license_date(end_raw, end_of_day=True)
    if start_dt is None or end_dt is None:
        return _base_status(
            "invalid",
            "subscription_invalid_dates",
            "Subscription dates are invalid or missing.",
        )
    if end_dt < start_dt:
        return _base_status(
            "invalid",
            "subscription_invalid_dates",
            "Subscription end date is before start date.",
        )

    now = now_tz()
    status = _base_status("active", "subscription_active", "Subscription is active.")
    status.update(
        {
            "subscriber_name": subscriber_name,
            "subscription_start_date": start_raw,
            "subscription_end_date": end_raw,
            "issued_at": issued_at,
            "issuer_id": issuer_id,
            "key_id": key_id,
            "key_source": str(key_meta.get("source", "")),
            "key_fingerprint_sha256": str(key_meta.get("fingerprint_sha256", "")),
        }
    )

    if now < start_dt:
        status.update(
            {
                "active": False,
                "state": "not_started",
                "code": "subscription_not_started",
                "message": "Subscription is not active yet.",
            }
        )
        return status

    if now > end_dt:
        status.update(
            {
                "active": False,
                "state": "expired",
                "code": "subscription_expired",
                "message": "Subscription has expired.",
                "expires_in_days": 0,
            }
        )
        return status

    days_remaining = max(0, (end_dt.date() - now.date()).days)
    status["expires_in_days"] = days_remaining
    status["expiring_soon"] = days_remaining <= subscription_warning_days()
    return status


def invalidate_subscription_cache() -> None:
    with _CACHE_LOCK:
        _CACHE["mtime_ns"] = None
        _CACHE["status"] = None


def get_subscription_status(*, force_refresh: bool = False) -> dict[str, Any]:
    license_path = subscription_license_path()
    mtime_ns = None
    if license_path.exists():
        try:
            mtime_ns = license_path.stat().st_mtime_ns
        except OSError:
            mtime_ns = None

    with _CACHE_LOCK:
        cached_mtime = _CACHE.get("mtime_ns")
        cached_status = _CACHE.get("status")
        if not force_refresh and cached_status and cached_mtime == mtime_ns:
            return dict(cached_status)

    if not license_path.exists():
        status = _base_status("missing", "subscription_missing", "Subscription file is missing.")
    else:
        try:
            raw_data = license_path.read_bytes()
            if len(raw_data) > _MAX_LICENSE_SIZE_BYTES:
                raise ValueError("Subscription file is too large.")
            license_doc = json.loads(raw_data.decode("utf-8"))
            if not isinstance(license_doc, dict):
                raise ValueError("Subscription file must be a JSON object.")
            status = _evaluate_license_document(license_doc)
        except Exception as exc:
            status = _base_status("invalid", "subscription_invalid_format", f"Subscription could not be read: {exc}")

    with _CACHE_LOCK:
        _CACHE["mtime_ns"] = mtime_ns
        _CACHE["status"] = dict(status)
    return status


def build_subscription_blocked_response(tool_name: str, status: dict[str, Any]) -> dict[str, Any]:
    code = str(status.get("code", "subscription_inactive"))
    state = str(status.get("state", "invalid"))
    details = {
        "state": state,
        "code": code,
        "message": str(status.get("message", "Subscription is required.")),
        "subscriber_name": str(status.get("subscriber_name", "")),
        "subscription_start_date": str(status.get("subscription_start_date", "")),
        "subscription_end_date": str(status.get("subscription_end_date", "")),
        "issuer_id": str(status.get("issuer_id", "")),
        "key_id": str(status.get("key_id", "")),
        "key_source": str(status.get("key_source", "")),
        "trust_mode": str(status.get("trust_mode", "")),
        "key_override_active": bool(status.get("key_override_active", False)),
        "expires_in_days": status.get("expires_in_days"),
    }
    return {
        "success": False,
        "error": details["message"],
        "code": code,
        "alert": f"Subscription check failed: {state}",
        "tool": str(tool_name),
        "subscription": details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

