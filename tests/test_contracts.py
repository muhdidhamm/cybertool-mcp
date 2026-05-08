import unittest

from tools.contracts import (
    AuditEvent,
    PlaybookDefinition,
    PlaybookMetadata,
    PlaybookStep,
    SessionSummary,
)


class ContractsTestCase(unittest.TestCase):
    def test_audit_event_contract(self) -> None:
        event = AuditEvent(timestamp="2026-01-01T00:00:00Z", event_type="tool.invoke", payload={"tool": "nmap_scan"})
        self.assertEqual(event.event_type, "tool.invoke")
        self.assertEqual(event.payload["tool"], "nmap_scan")

    def test_session_summary_contract(self) -> None:
        session = SessionSummary(
            id="s-1",
            caption="Example",
            start="2026-01-01T00:00:00Z",
            end="2026-01-01T00:01:00Z",
            event_count=4,
            tools=["nmap_scan"],
        )
        self.assertEqual(session.chat_turn_count, 0)
        self.assertEqual(session.tools, ["nmap_scan"])

    def test_playbook_contract(self) -> None:
        playbook = PlaybookDefinition(
            metadata=PlaybookMetadata(name="demo"),
            steps=[
                PlaybookStep(
                    id="scan",
                    tool="nmap_scan",
                    args={"target": "{{target}}"},
                    depends_on=[],
                )
            ],
        )
        self.assertEqual(playbook.metadata.name, "demo")
        self.assertEqual(playbook.steps[0].tool, "nmap_scan")


if __name__ == "__main__":
    unittest.main()
