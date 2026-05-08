import os
import tempfile
import asyncio
import unittest

from tools.playbooks import (
    clone_playbook,
    create_or_update_playbook,
    delete_playbook,
    ensure_playbook_store,
    get_playbook,
    list_playbooks,
    validate_playbook_yaml,
    run_playbook_runtime,
)


VALID_YAML = """\
metadata:
  name: sample
  description: Demo
  tags: [demo]
  owner: analyst
  source: test
  updated_at: "2026-01-01T00:00:00Z"
  version: 1
inputs:
  target: ""
  extra: {}
steps:
  - id: step1
    tool: nmap_scan
    args:
      target: "{{target}}"
      ports: "1-100"
    depends_on: []
    retries: 0
    timeout_seconds: 120
    on_failure: stop
retry_policy: {}
guardrails: {}
output_contract: {}
"""


class PlaybookStoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.old_dir = os.environ.get("MCP_PLAYBOOKS_DIR", "")
        os.environ["MCP_PLAYBOOKS_DIR"] = self.tmp.name
        ensure_playbook_store()

    def tearDown(self) -> None:
        if self.old_dir:
            os.environ["MCP_PLAYBOOKS_DIR"] = self.old_dir
        else:
            os.environ.pop("MCP_PLAYBOOKS_DIR", None)
        self.tmp.cleanup()

    def test_validate_playbook_yaml(self) -> None:
        result = validate_playbook_yaml(VALID_YAML)
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_create_get_and_list_playbook(self) -> None:
        created = create_or_update_playbook("sample", VALID_YAML)
        self.assertTrue(created["success"])
        loaded = get_playbook("sample")
        self.assertTrue(loaded["valid"])
        rows = list_playbooks()
        self.assertTrue(any(row["name"] == "sample" for row in rows))

    def test_clone_and_delete_playbook(self) -> None:
        create_or_update_playbook("sample", VALID_YAML)
        cloned = clone_playbook("sample", "sample_copy")
        self.assertTrue(cloned["success"])
        deleted = delete_playbook("sample_copy", soft_delete=True)
        self.assertTrue(deleted["success"])

    def test_run_playbook_runtime(self) -> None:
        create_or_update_playbook("sample", VALID_YAML)

        async def fake_tool(target: str, ports: str) -> dict:
            return {"success": True, "target": target, "ports": ports}

        run = asyncio.run(run_playbook_runtime("sample", "example.com", {"nmap_scan": fake_tool}))
        self.assertEqual(run["status"], "success")
        self.assertEqual(len(run["steps"]), 1)

    def test_run_playbook_runtime_with_variables(self) -> None:
        custom_yaml = VALID_YAML.replace("{{target}}", "{{asset_host}}")
        create_or_update_playbook("sample_vars", custom_yaml)

        async def fake_tool(target: str, ports: str) -> dict:
            return {"success": True, "target": target, "ports": ports}

        run = asyncio.run(
            run_playbook_runtime(
                "sample_vars",
                "example.com",
                {"nmap_scan": fake_tool},
                variables={"asset_host": "internal.example.com"},
            )
        )
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["steps"][0]["output"]["target"], "internal.example.com")


if __name__ == "__main__":
    unittest.main()
