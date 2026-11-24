import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_dashboard
import agent_demo
import agent_skill_gate as gate


class DemoTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.real_home = self.base / "real-home"
        self.real_home.mkdir()
        for path in (".agents/skills/keep", ".claude/skills/keep", ".local/share/agent-skills/keep", ".agent-staging/reports/keep", "Downloads/keep"):
            target = self.real_home / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("unchanged")
        for context in (
            patch.object(Path, "home", return_value=self.real_home),
            patch.object(sys.stdin, "isatty", return_value=True),
            patch.object(agent_demo.tempfile, "tempdir", str(self.base)),
            patch.dict(os.environ, {"AGENT_GATE_STAGING": str(self.real_home / ".agent-staging"), "AGENT_GATE_VAULT": str(self.real_home / ".local/share/agent-skills")}),
        ):
            context.__enter__()
            self.addCleanup(context.__exit__, None, None, None)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def snapshot(self):
        return {str(path.relative_to(self.real_home)): (path.lstat().st_ino, path.lstat().st_mtime_ns)
                for path in self.real_home.rglob("*")}

    def cli(self, *arguments):
        with patch.object(sys, "argv", ["agent_skill_gate.py", *arguments]):
            return gate.main()

    def test_repeated_demo_is_fresh_cleans_up_and_never_calls_external_tools(self):
        before = self.snapshot()
        original_home_env = os.environ.get("HOME")
        for _ in range(2):
            with patch.object(gate, "probe", side_effect=AssertionError("external probe")) as probe, patch.object(gate.subprocess, "run", side_effect=AssertionError("external command")) as run, patch.object(gate, "confirm", return_value=True), patch("builtins.input", side_effect=["s", "n"]):
                self.assertEqual(self.cli("setup", "--demo"), 0)
            probe.assert_not_called()
            run.assert_not_called()
            self.assertEqual(list(self.base.glob("agent-skill-gate-demo-*")), [])
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(Path.home(), self.real_home)
            self.assertEqual(os.environ.get("HOME"), original_home_env)
        self.assertIn("SIMULATED SCANNER RESULTS", self.output.getvalue())
        self.assertEqual(self.output.getvalue().count("Demo files removed:"), 2)

    def test_keep_demo_retains_only_scratch_reports_and_marks_simulation(self):
        before = self.snapshot()
        with patch.object(gate, "confirm", return_value=True), patch("builtins.input", side_effect=["s", "n"]):
            self.assertEqual(self.cli("setup", "--demo", "--keep-demo"), 0)
        roots = list(self.base.glob("agent-skill-gate-demo-*"))
        self.assertEqual(len(roots), 1)
        reports = list((roots[0] / "home/Downloads").glob("*.md"))
        self.assertEqual(len(reports), 1)
        self.assertIn("SIMULATED RESULTS", reports[0].read_text())
        self.assertEqual(self.snapshot(), before)

    def test_cancellation_removes_scratch_state_and_restores_overrides(self):
        before = self.snapshot()
        with patch.object(gate, "confirm", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cli("setup", "--demo"), 130)
        self.assertEqual(list(self.base.glob("agent-skill-gate-demo-*")), [])
        self.assertEqual(Path.home(), self.real_home)
        self.assertEqual(self.snapshot(), before)

    def test_cancellation_during_review_also_cleans_up(self):
        with patch.object(gate, "confirm", return_value=True), patch("builtins.input", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cli("setup", "--demo"), 130)
        self.assertEqual(list(self.base.glob("agent-skill-gate-demo-*")), [])

    def test_real_scan_mode_uses_original_scanner_on_scratch_inputs(self):
        before = self.snapshot()
        payloads = []

        def scan(payload):
            self.assertTrue(payload.is_relative_to(self.base))
            self.assertFalse(payload.is_relative_to(self.real_home))
            payloads.append(payload)
            # This test mocks real Docker, not the demo's simulated scanner.
            return 0, {"risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE"}, "issues": []}, ""

        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "scanner_self_test", return_value=True), patch.object(gate, "docker_scan", side_effect=scan), patch.object(gate, "confirm", return_value=True), patch("builtins.input", return_value="s"):
            self.assertEqual(self.cli("setup", "--demo", "--real-scan"), 0)
        self.assertEqual(len(payloads), 4)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.base.glob("agent-skill-gate-demo-*")), [])

    def test_demo_rejects_real_destination_overrides_and_orphan_flags(self):
        commands = (
            ("setup", "--real-scan"), ("setup", "--keep-demo"),
            ("--vault", str(self.real_home), "setup", "--demo"),
            ("--staging", str(self.real_home), "setup", "--demo"),
            ("setup", "--demo", "--report-output", str(self.real_home / "Downloads/unsafe.md")),
        )
        before = self.snapshot()
        for arguments in commands:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                self.cli(*arguments)
            self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.snapshot(), before)

    def test_demo_cannot_follow_actual_linux_downloads_configuration(self):
        before = self.snapshot()
        with patch.object(agent_dashboard.sys, "platform", "linux"), patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.real_home / ".config")}), patch.object(gate, "confirm", return_value=True), patch("builtins.input", side_effect=["s", "n"]):
            self.assertEqual(self.cli("setup", "--demo", "--keep-demo"), 0)
        self.assertEqual(self.snapshot(), before)
        root = next(self.base.glob("agent-skill-gate-demo-*"))
        self.assertTrue(list((root / "home/Downloads").glob("*.md")))

    def test_noninteractive_demo_does_not_create_a_profile(self):
        with patch.object(sys.stdin, "isatty", return_value=False), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cli("setup", "--demo"), 1)
        self.assertEqual(list(self.base.glob("agent-skill-gate-demo-*")), [])


if __name__ == "__main__":
    unittest.main()
