import base64
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from urllib import request

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import tools.dashboard_server as legacy_dashboard
from tools.dashboard_fastapi import create_dashboard_app
from tools.subscription import (
    build_subscription_blocked_response,
    get_subscription_status,
    invalidate_subscription_cache,
)


def _canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _DummyMcp:
    _tool_manager = None


class SubscriptionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._env_backup = {
            "MCP_SUBSCRIPTION_LICENSE_PATH": os.environ.get("MCP_SUBSCRIPTION_LICENSE_PATH"),
            "MCP_SUBSCRIPTION_PUBLIC_KEY_PEM": os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PEM"),
            "MCP_SUBSCRIPTION_PUBLIC_KEY_PATH": os.environ.get("MCP_SUBSCRIPTION_PUBLIC_KEY_PATH"),
            "MCP_SUBSCRIPTION_TRUST_MODE": os.environ.get("MCP_SUBSCRIPTION_TRUST_MODE"),
            "MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE": os.environ.get("MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE"),
            "MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT": os.environ.get("MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT"),
            "MCP_SUBSCRIPTION_KEYRING_PATH": os.environ.get("MCP_SUBSCRIPTION_KEYRING_PATH"),
            "MCP_SUBSCRIPTION_PINNED_PUBLIC_KEY_PATH": os.environ.get("MCP_SUBSCRIPTION_PINNED_PUBLIC_KEY_PATH"),
            "MCP_SUBSCRIPTION_PINNED_KEY_FINGERPRINT_SHA256": os.environ.get("MCP_SUBSCRIPTION_PINNED_KEY_FINGERPRINT_SHA256"),
            "MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS": os.environ.get("MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS"),
            "MCP_DASHBOARD_AUTH_TOKEN": os.environ.get("MCP_DASHBOARD_AUTH_TOKEN"),
            "MCP_DASHBOARD_USERNAME": os.environ.get("MCP_DASHBOARD_USERNAME"),
            "MCP_DASHBOARD_PASSWORD": os.environ.get("MCP_DASHBOARD_PASSWORD"),
            "MCP_DASHBOARD_PASSWORD_HASH": os.environ.get("MCP_DASHBOARD_PASSWORD_HASH"),
        }

        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_path = os.path.join(self.tmp.name, "subscription-public.pem")
        with open(self.public_key_path, "wb") as f:
            f.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(der)
        self.public_key_fingerprint = base64.b64encode(digest.finalize()).decode("ascii")

        self.license_path = os.path.join(self.tmp.name, "subscription.lic")
        self.keyring_path = os.path.join(self.tmp.name, "keys.json")
        with open(self.keyring_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "keys": [
                        {
                            "issuer_id": "cybertool-mcp",
                            "key_id": "vendor-default-2026",
                            "public_key_path": self.public_key_path,
                            "fingerprint_sha256": self.public_key_fingerprint,
                        }
                    ]
                },
                f,
            )
        os.environ["MCP_SUBSCRIPTION_LICENSE_PATH"] = self.license_path
        os.environ["MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS"] = "14"
        os.environ["MCP_SUBSCRIPTION_TRUST_MODE"] = "prod"
        os.environ["MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE"] = "false"
        os.environ["MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT"] = "true"
        os.environ["MCP_SUBSCRIPTION_KEYRING_PATH"] = self.keyring_path
        os.environ.pop("MCP_SUBSCRIPTION_PINNED_PUBLIC_KEY_PATH", None)
        os.environ.pop("MCP_SUBSCRIPTION_PINNED_KEY_FINGERPRINT_SHA256", None)
        os.environ.pop("MCP_SUBSCRIPTION_PUBLIC_KEY_PEM", None)
        os.environ.pop("MCP_SUBSCRIPTION_PUBLIC_KEY_PATH", None)

        # Disable dashboard auth for API endpoint tests.
        os.environ.pop("MCP_DASHBOARD_AUTH_TOKEN", None)
        os.environ.pop("MCP_DASHBOARD_USERNAME", None)
        os.environ.pop("MCP_DASHBOARD_PASSWORD", None)
        os.environ.pop("MCP_DASHBOARD_PASSWORD_HASH", None)

        invalidate_subscription_cache()

    def tearDown(self) -> None:
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        invalidate_subscription_cache()
        self.tmp.cleanup()

    def _write_license(self, payload: dict, *, tamper_signature: bool = False) -> None:
        signature = self.private_key.sign(_canonical_payload_bytes(payload))
        signature_b64 = base64.b64encode(signature).decode("ascii")
        if tamper_signature:
            signature_b64 = signature_b64[:-2] + "AA"
        data = {"payload": payload, "signature": signature_b64}
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        invalidate_subscription_cache()

    def test_active_subscription_status(self) -> None:
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Acme Corp",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=30)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        self._write_license(payload)
        status = get_subscription_status(force_refresh=True)
        self.assertTrue(status["active"])
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["subscriber_name"], "Acme Corp")

    def test_expired_subscription_status(self) -> None:
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Acme Corp",
            "subscription_start_date": str(today - timedelta(days=20)),
            "subscription_end_date": str(today - timedelta(days=1)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        self._write_license(payload)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["state"], "expired")

    def test_missing_subscription_status(self) -> None:
        if os.path.exists(self.license_path):
            os.remove(self.license_path)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["state"], "missing")

    def test_invalid_signature_status(self) -> None:
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Acme Corp",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=3)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        self._write_license(payload, tamper_signature=True)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["state"], "invalid")

    def test_strict_schema_rejects_unknown_payload_fields(self) -> None:
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Acme Corp",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=3)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
            "plan": "gold",
        }
        self._write_license(payload)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["code"], "subscription_invalid_schema")

    def test_strict_schema_rejects_unknown_top_level_fields(self) -> None:
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Acme Corp",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=3)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        signature = base64.b64encode(self.private_key.sign(_canonical_payload_bytes(payload))).decode("ascii")
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "signature": signature, "extra": "x"}, f)
        invalidate_subscription_cache()
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["code"], "subscription_invalid_schema")

    def test_blocked_response_shape(self) -> None:
        response = build_subscription_blocked_response(
            "nmap_scan",
            {
                "state": "expired",
                "code": "subscription_expired",
                "message": "Subscription has expired.",
                "subscriber_name": "Acme Corp",
                "subscription_start_date": "2026-01-01",
                "subscription_end_date": "2026-03-31",
                "expires_in_days": 0,
            },
        )
        self.assertFalse(response["success"])
        self.assertEqual(response["code"], "subscription_expired")
        self.assertEqual(response["tool"], "nmap_scan")

    def test_dashboard_subscription_status_and_upload(self) -> None:
        app = create_dashboard_app(_DummyMcp())
        client = TestClient(app)

        status_res = client.get("/api/subscription/status")
        self.assertEqual(status_res.status_code, 200)
        self.assertEqual(status_res.json()["subscription"]["state"], "missing")

        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Upload Inc",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=5)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        signature = base64.b64encode(self.private_key.sign(_canonical_payload_bytes(payload))).decode("ascii")
        blob = json.dumps({"payload": payload, "signature": signature}).encode("utf-8")
        upload_res = client.post(
            "/api/subscription/upload",
            content=blob,
            headers={"Content-Type": "application/octet-stream", "X-Subscription-Filename": "subscription.lic"},
        )
        self.assertEqual(upload_res.status_code, 200)
        self.assertTrue(upload_res.json()["subscription"]["active"])

        bad_upload_res = client.post(
            "/api/subscription/upload",
            content=blob,
            headers={"Content-Type": "application/octet-stream", "X-Subscription-Filename": "alt.lic"},
        )
        self.assertEqual(bad_upload_res.status_code, 200)
        self.assertTrue(bad_upload_res.json()["success"])

    def test_prod_mode_ignores_key_override_env(self) -> None:
        override_private = ed25519.Ed25519PrivateKey.generate()
        override_public = override_private.public_key()
        override_path = os.path.join(self.tmp.name, "override-public.pem")
        with open(override_path, "wb") as f:
            f.write(
                override_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        os.environ["MCP_SUBSCRIPTION_TRUST_MODE"] = "prod"
        os.environ["MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE"] = "false"
        os.environ["MCP_SUBSCRIPTION_PUBLIC_KEY_PATH"] = override_path

        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Prod Locked",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=5)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        signature = base64.b64encode(override_private.sign(_canonical_payload_bytes(payload))).decode("ascii")
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "signature": signature}, f)
        invalidate_subscription_cache()

        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["code"], "subscription_invalid_signature")
        self.assertFalse(status["key_override_active"])

    def test_dev_mode_allows_override_only_with_both_flags(self) -> None:
        override_private = ed25519.Ed25519PrivateKey.generate()
        override_public = override_private.public_key()
        override_path = os.path.join(self.tmp.name, "override-2-public.pem")
        with open(override_path, "wb") as f:
            f.write(
                override_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        os.environ["MCP_SUBSCRIPTION_TRUST_MODE"] = "dev"
        os.environ["MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE"] = "true"
        os.environ["MCP_SUBSCRIPTION_PUBLIC_KEY_PATH"] = override_path

        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Dev Override",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=2)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "x",
            "key_id": "y",
        }
        signature = base64.b64encode(override_private.sign(_canonical_payload_bytes(payload))).decode("ascii")
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "signature": signature}, f)
        invalidate_subscription_cache()

        status = get_subscription_status(force_refresh=True)
        self.assertTrue(status["active"])
        self.assertTrue(status["key_override_active"])
        self.assertEqual(status["key_source"], "override")

    def test_keyring_fingerprint_mismatch_fails_closed(self) -> None:
        with open(self.keyring_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "keys": [
                        {
                            "issuer_id": "cybertool-mcp",
                            "key_id": "vendor-default-2026",
                            "public_key_path": self.public_key_path,
                            "fingerprint_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        }
                    ]
                },
                f,
            )
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "Bad Fingerprint",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=3)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer_id": "cybertool-mcp",
            "key_id": "vendor-default-2026",
        }
        self._write_license(payload)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["code"], "subscription_invalid_format")
        self.assertIn("Fingerprint mismatch", status["message"])

    def test_legacy_compat_toggle_requires_issuer_fields(self) -> None:
        os.environ["MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT"] = "false"
        today = datetime.now(timezone.utc).date()
        payload = {
            "subscriber_name": "No Issuer Fields",
            "subscription_start_date": str(today - timedelta(days=1)),
            "subscription_end_date": str(today + timedelta(days=3)),
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        self._write_license(payload)
        status = get_subscription_status(force_refresh=True)
        self.assertFalse(status["active"])
        self.assertEqual(status["code"], "subscription_invalid_schema")

    def test_legacy_dashboard_subscription_status_and_upload(self) -> None:
        legacy_dashboard._MCP_INSTANCE = _DummyMcp()
        server = ThreadingHTTPServer(("127.0.0.1", 0), legacy_dashboard._DashboardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            status_url = f"http://{host}:{port}/api/subscription/status"
            with request.urlopen(status_url, timeout=3) as res:
                payload = json.loads(res.read().decode("utf-8"))
            self.assertEqual(payload["subscription"]["state"], "missing")

            today = datetime.now(timezone.utc).date()
            doc_payload = {
                "subscriber_name": "Legacy Upload Inc",
                "subscription_start_date": str(today - timedelta(days=1)),
                "subscription_end_date": str(today + timedelta(days=7)),
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "issuer_id": "cybertool-mcp",
                "key_id": "vendor-default-2026",
            }
            signature = base64.b64encode(self.private_key.sign(_canonical_payload_bytes(doc_payload))).decode("ascii")
            body = json.dumps({"payload": doc_payload, "signature": signature}).encode("utf-8")
            upload_req = request.Request(
                f"http://{host}:{port}/api/subscription/upload",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Subscription-Filename": "subscription.lic",
                },
            )
            with request.urlopen(upload_req, timeout=3) as res:
                upload_payload = json.loads(res.read().decode("utf-8"))
            self.assertTrue(upload_payload["success"])
            self.assertTrue(upload_payload["subscription"]["active"])

            alt_upload_req = request.Request(
                f"http://{host}:{port}/api/subscription/upload",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Subscription-Filename": "not-allowed.lic",
                },
            )
            with request.urlopen(alt_upload_req, timeout=3) as res:
                alt_upload_payload = json.loads(res.read().decode("utf-8"))
            self.assertTrue(alt_upload_payload["success"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

