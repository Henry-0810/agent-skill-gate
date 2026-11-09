import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_dashboard as dashboard
import agent_review as review
import agent_skill_gate as gate
from test_review import report


def record(name="demo-safe", action="pending", recommendation="SAFE"):
    return {
        "job": "review-demo", "skill": name, "source": "/backups/codex-slot/skills/" + name,
        "agent": "codex", "action": action, "time": "2026-11-09T01:00:00+00:00",
        "scanner_exit": 0, "scanner": report(recommendation), "human_approved": False,
    }


class DashboardTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name).resolve() / "home"
        self.home.mkdir()
        self.stage = self.home / "stage"
        (self.stage / "reports").mkdir(parents=True)
        home = patch.object(Path, "home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.home / ".config")})
        env.start()
        self.addCleanup(env.stop)

    def test_macos_downloads_and_new_private_report(self):
        with patch.object(dashboard.sys, "platform", "darwin"):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Downloads")
            local, exported = dashboard.export_dashboard([record()], self.stage)
        self.assertEqual(exported.parent, self.home / "Downloads")
        self.assertEqual(exported.read_text(), local.read_text())
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)

    def test_linux_honors_xdg_downloads_without_shell_execution(self):
        config = self.home / ".config"
        config.mkdir()
        (config / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Incoming files"\n')
        with patch.object(dashboard.sys, "platform", "linux"):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Incoming files")
        (config / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$(touch /tmp/never-run)"\n')
        with patch.object(dashboard.sys, "platform", "linux"):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Downloads")

    def test_linux_absolute_custom_config_and_relative_setting_fallback(self):
        config = self.home / ".config"
        config.mkdir()
        (config / "user-dirs.dirs").write_text(f'XDG_DOWNLOAD_DIR="{self.home}/Localized"\n')
        with patch.object(dashboard.sys, "platform", "linux"):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Localized")
        (config / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="relative/path"\n')
        with patch.object(dashboard.sys, "platform", "linux"):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Downloads")

    def test_windows_uses_known_folder_and_falls_back_safely(self):
        configured = self.home / "RedirectedDownloads"
        with patch.object(dashboard.sys, "platform", "win32"), patch.object(dashboard, "_windows_downloads", return_value=configured) as lookup:
            self.assertEqual(dashboard.downloads_directory(), configured)
            lookup.assert_called_once()
        with patch.object(dashboard.sys, "platform", "win32"), patch.object(dashboard, "_windows_downloads", side_effect=OSError):
            self.assertEqual(dashboard.downloads_directory(), self.home / "Downloads")

    def test_existing_output_file_or_link_is_never_overwritten(self):
        existing = self.home / "existing.md"
        existing.write_text("keep")
        with self.assertRaises(FileExistsError):
            dashboard.write_markdown(existing, "replacement")
        link = self.home / "link.md"
        link.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            dashboard.write_markdown(link, "replacement")
        self.assertEqual(existing.read_text(), "keep")
        self.assertTrue(link.is_symlink())

    def test_export_failure_keeps_local_dashboard_and_does_not_raise(self):
        existing = self.home / "existing.md"
        existing.write_text("keep")
        with contextlib.redirect_stdout(io.StringIO()):
            local, exported = dashboard.export_dashboard([record()], self.stage, output=existing)
        self.assertIsNone(exported)
        self.assertTrue(local.is_file())
        self.assertEqual(existing.read_text(), "keep")

    def test_markdown_has_real_findings_coverage_outcomes_and_source(self):
        safe = record(action="promote")
        safe["scanner"]["issues"] = [{"id": "AR2", "severity": "HIGH", "finding": "Suppresses security warnings", "explanation": "The instruction asks the agent to omit caveats.", "location": {"file": "SKILL.md", "start_line": 69}, "remediation": "Allow security caveats."}]
        blocked = record("obsidian-bases", "quarantine", "CAUTION")
        blocked["scanner"]["analysis_completeness"].update(is_complete=False, coverage_percent=66.7)
        blocked["reason"] = "Scanner analysis is incomplete"
        skipped = record("existing", "skip")
        skipped.pop("scanner")
        content = dashboard.render_dashboard([safe, blocked, skipped])
        for text in ("66.7%", "HIGH", "AR2", "Suppresses security warnings", "omit caveats", "Allow security caveats", "Blocked", "not rescanned", "not a clean verdict", "0 to 100", "backup area"):
            self.assertIn(text, content)
        self.assertIn("/backups/codex", content)

    def test_untrusted_markdown_and_terminal_controls_are_escaped(self):
        value = record("![leak](https://bad.example/x)")
        value["scanner"]["issues"] = [{"severity": "HIGH", "finding": "<script>alert(1)</script>\x1b[2J\n![image](https://bad.example)"}]
        content = dashboard.render_dashboard([value])
        self.assertNotIn("<script>", content)
        self.assertNotIn("\x1b", content)
        self.assertNotIn("![image](", content)
        self.assertIn("&lt;script&gt;", content)

    def test_saved_reports_load_without_mutation_and_filter_runs(self):
        original = record(action="promote")
        original["run_id"] = "first-run"
        file = self.stage / "reports" / "review-demo.json"
        file.write_text(json.dumps(original))
        before = file.read_bytes(), file.stat().st_mtime_ns
        records, warnings = dashboard.load_review_reports(self.stage, run_id="first-run")
        self.assertEqual(len(records), 1)
        self.assertEqual(warnings, [])
        self.assertEqual((file.read_bytes(), file.stat().st_mtime_ns), before)
        self.assertEqual(dashboard.load_review_reports(self.stage, run_id="other")[0], [])

    def test_malformed_or_symlinked_history_is_reported_not_followed(self):
        (self.stage / "reports" / "review-bad.json").write_text("not json")
        outside = self.home / "outside.json"
        outside.write_text(json.dumps(record()))
        (self.stage / "reports" / "review-link.json").symlink_to(outside)
        records, warnings = dashboard.load_review_reports(self.stage)
        self.assertEqual(records, [])
        self.assertEqual(len(warnings), 2)

    def test_export_cli_does_not_need_terminal_docker_or_watchman(self):
        (self.stage / "reports" / "review-demo.json").write_text(json.dumps(record(action="promote")))
        output = self.home / "custom.md"
        with patch.object(sys, "argv", ["agent_skill_gate.py", "--staging", str(self.stage), "export-report", "--output", str(output)]), patch.object(sys.stdin, "isatty", return_value=False), patch.object(gate, "docker_scan") as scan, patch.object(gate, "probe") as probe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 0)
        self.assertTrue(output.is_file())
        scan.assert_not_called()
        probe.assert_not_called()


class SelectionTest(unittest.TestCase):
    def test_safe_group_excludes_caution_and_blocked_rows(self):
        records = [record(), record("caution", recommendation="CAUTION"), record("blocked", action="quarantine")]
        self.assertEqual(review.parse_review_selection("s", records), ("safe-group", [0]))
        self.assertEqual(review.parse_review_selection("1,2", records), ("selected", [0, 1]))
        with self.assertRaises(ValueError):
            review.parse_review_selection("3", records)

    def test_no_selection_from_invalid_input_and_default_no(self):
        for value in ("yes", "0", "-1", "1,99", "1;touch a", "v 0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.parse_review_selection(value, [record()])
        self.assertEqual(review.parse_review_selection("", [record()]), ("finish", []))
        self.assertEqual(review.parse_review_selection("v 1", [record()]), ("view", [0]))

    def test_terminal_table_supports_narrow_width_and_high_findings(self):
        value = record()
        value["scanner"]["issues"] = [{"severity": "HIGH", "finding": "Actual finding"}]
        with patch.object(review.shutil, "get_terminal_size", return_value=os.terminal_size((70, 24))):
            output = review.review_table([value])
        self.assertIn("highest HIGH", output)
        self.assertIn("risk 8/100", output)
        self.assertEqual(review.finding_text(value["scanner"]["issues"][0]), "Actual finding")


if __name__ == "__main__":
    unittest.main()
