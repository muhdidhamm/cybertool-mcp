import unittest

from tools.reporting import generate_executive_summary_from_session


class ReportingPipelineTestCase(unittest.TestCase):
    def test_unknown_session_returns_error(self) -> None:
        result = generate_executive_summary_from_session("missing-session")
        self.assertFalse(result["success"])
        self.assertIn("Unknown session", result["error"])


if __name__ == "__main__":
    unittest.main()
