import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_skill_gate as gate


class SkillGateTest(unittest.TestCase):
    def setUp(self):
        notifications = patch.object(gate, "notify")
        notifications.start()
        self.addCleanup(notifications.stop)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        base = Path(self.dir.name).resolve()
        self.stage, self.vault = base / "stage", base / "vault"
        gate.initialize(self.stage, self.vault)
        self.source = self.stage / "build" / "demo-safe"
        self.source.mkdir()
        (self.source / "SKILL.md").write_text(
            "---\nname: demo-safe\ndescription: Documentation helper\n---\n# Demo\nRead text.\n"
        )

    @staticmethod
    def scan(recommendation="SAFE", exitcode=0):
        return (exitcode, {
            "risk_assessment": {
                "recommendation": recommendation, "score": 0,
                "severity": "LOW" if recommendation == "SAFE" else "MEDIUM",
            },
            "issues": [],
        }, "")

    def test_safe_skill_is_promoted(self):
        gate.submit(self.source, self.stage)
        with patch.object(gate, "docker_scan", return_value=self.scan()):
            result = gate.process(self.stage, self.vault)
        self.assertEqual(result[0]["action"], "promote")
        self.assertTrue((self.vault / "demo-safe" / "SKILL.md").is_file())
        self.assertEqual(len(list((self.stage / "quarantine").iterdir())), 0)

    def test_caution_exit_zero_is_quarantined(self):
        gate.submit(self.source, self.stage)
        with patch.object(gate, "docker_scan", return_value=self.scan("CAUTION", 0)):
            result = gate.process(self.stage, self.vault)
        self.assertEqual(result[0]["action"], "quarantine")
        self.assertFalse((self.vault / "demo-safe").exists())
        self.assertEqual(len(list((self.stage / "quarantine").iterdir())), 1)

    def test_scanner_error_blocks(self):
        gate.submit(self.source, self.stage)
        with patch.object(gate, "docker_scan", return_value=(2, {}, "docker is unavailable")):
            result = gate.process(self.stage, self.vault)
        self.assertEqual(result[0]["action"], "quarantine")

    def test_symlink_in_skill_fails_submitting(self):
        (self.source / "secret").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            gate.submit(self.source, self.stage)
        self.assertEqual(list((self.stage / "incoming").iterdir()), [])

    def test_no_overwrite(self):
        installed = self.vault / "demo-safe"
        installed.mkdir()
        (installed / "SKILL.md").write_text("original")
        gate.submit(self.source, self.stage)
        with patch.object(gate, "docker_scan", return_value=self.scan()):
            result = gate.process(self.stage, self.vault)
        self.assertEqual(result[0]["action"], "quarantine")
        self.assertEqual((installed / "SKILL.md").read_text(), "original")

    def test_detect_snapshot_modification(self):
        gate.submit(self.source, self.stage)
        def tamper(payload):
            (payload / "SKILL.md").write_text("changed after scan")
            return self.scan()
        with patch.object(gate, "docker_scan", side_effect=tamper):
            result = gate.process(self.stage, self.vault)
        self.assertEqual(result[0]["action"], "quarantine")
        self.assertIn("TOCTOU", result[0]["reason"])

    def test_missing_ready_skipped(self):
        job = self.stage / "incoming" / "demo-safe--abcdef"
        job.mkdir()
        (job / "payload").mkdir()
        self.assertEqual(gate.process(self.stage, self.vault), [])


if __name__ == "__main__":
    unittest.main()
