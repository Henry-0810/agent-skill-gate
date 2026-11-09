import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_review as review
import agent_skill_gate as gate


def report(recommendation="SAFE", score=8, severity="LOW"):
    return {
        "risk_assessment": {"recommendation": recommendation, "score": score, "severity": severity},
        "issues": [],
        "analysis_completeness": {"is_complete": True, "coverage_percent": 100, "execution_successful": True},
        "metadata": {"skillspector_version": "test", "llm_requested": False, "execution_successful": True},
    }


class PolicyTest(unittest.TestCase):
    def test_safe_is_eligible_but_caution_needs_manual_policy(self):
        self.assertIsNone(review.scan_problem(0, report()))
        caution = report("CAUTION", 35, "MEDIUM")
        self.assertIsNotNone(review.scan_problem(0, caution))
        self.assertIsNone(review.scan_problem(0, caution, allow_caution=True))

    def test_high_risk_never_becomes_eligible(self):
        for value in (report("DO_NOT_INSTALL", 80, "HIGH"), report("SAFE", 80, "LOW"), report("CAUTION", 20, "CRITICAL")):
            with self.subTest(value=value):
                self.assertIsNotNone(review.scan_problem(0, value, allow_caution=True))

    def test_nonzero_exit_always_blocks(self):
        for code in (1, 2, -9):
            self.assertIsNotNone(review.scan_problem(code, report(), allow_caution=True))

    def test_malformed_reports_fail_closed(self):
        values = [None, [], "SAFE", {}, {"risk_assessment": []}]
        for key, value in (("score", None), ("score", True), ("score", "0"), ("score", float("nan")), ("score", float("inf")), ("score", -1), ("score", 101), ("recommendation", []), ("severity", {}), ("severity", None)):
            candidate = report()
            candidate["risk_assessment"][key] = value
            values.append(candidate)
        for value in values:
            with self.subTest(value=value):
                self.assertIsNotNone(review.scan_problem(0, value, allow_caution=True))

    def test_incomplete_metadata_blocks_even_with_exit_zero(self):
        for completeness in (None, {}, [], {"is_complete": False}, {"is_complete": "true"}, {"is_complete": True, "execution_successful": False}):
            value = report("CAUTION", 15)
            value["analysis_completeness"] = completeness
            self.assertIsNotNone(review.scan_problem(0, value, allow_caution=True))

    def test_unsuccessful_execution_blocks(self):
        value = report()
        value["metadata"]["execution_successful"] = False
        self.assertIsNotNone(review.scan_problem(0, value))

    def test_terminal_controls_are_escaped(self):
        rendered = review.visible("hello\x1b[2J\r\n\u202Eworld")
        for control in ("\x1b", "\r", "\n", "\u202e"):
            self.assertNotIn(control, rendered)
        self.assertIn("\\x1b", rendered)

    def test_confirmation_defaults_to_no_and_handles_eof(self):
        for response in ("", "n", "no"):
            with patch("builtins.input", return_value=response):
                self.assertFalse(review.confirm("Install?"))
        with patch("builtins.input", side_effect=EOFError):
            self.assertFalse(review.confirm("Install?"))
        with patch("builtins.input", return_value="yes"):
            self.assertTrue(review.confirm("Install?"))

    def test_invalid_confirmation_does_not_count_as_approval(self):
        with patch("builtins.input", side_effect=["sure", "n"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(review.confirm("Install?"))


class ReviewTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir()
        self.stage = self.home / "stage"
        self.vault = self.home / ".local" / "share" / "agent-skills"
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for target, name, value in ((Path, "home", self.home), (sys.stdin, "isatty", True)):
            context = patch.object(target, name, return_value=value)
            context.start()
            self.addCleanup(context.stop)
        notifications = patch.object(gate, "notify")
        notifications.start()
        self.addCleanup(notifications.stop)
        services = patch.object(gate, "probe", side_effect=RuntimeError("external services are mocked"))
        services.start()
        self.addCleanup(services.stop)
        gate.initialize(self.stage, self.vault)
        self.backups = self.home / ".local" / "state" / "agent-skill-gate" / "backups"

    def backup(self, name="demo-safe", *, agent="codex", nested=""):
        source = self.backups / f"{agent}-test-slot" / "skills" / nested / name
        source.mkdir(parents=True)
        (source / "SKILL.md").write_text("# Documentation helper\nSummarize public text.\n")
        return review.BackupSkill(agent, source)

    def results(self):
        return [json.loads(path.read_text()) for path in sorted((self.stage / "reports").glob("review-*.json"))]

    def cli(self, *arguments):
        argv = ["agent_skill_gate.py", "--staging", str(self.stage), "--vault", str(self.vault), *arguments]
        with patch.object(sys, "argv", argv):
            return gate.main()

    def snapshot(self):
        return {
            str(path.relative_to(self.base)): (path.lstat().st_ino, path.lstat().st_mode, path.lstat().st_mtime_ns)
            for path in self.base.rglob("*")
        }

    def test_safe_approval_installs_snapshot_preserving_original(self):
        skill = self.backup()
        before = gate.fingerprint(skill.source)
        inode = skill.source.stat().st_ino
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", return_value=True):
            result = gate.review_backup(skill, self.stage, self.vault)
        self.assertEqual(result["action"], "promote")
        self.assertTrue(result["human_approved"])
        self.assertEqual(gate.fingerprint(skill.source), before)
        self.assertEqual(skill.source.stat().st_ino, inode)
        self.assertEqual(gate.fingerprint(self.vault / skill.source.name), before)
        self.assertEqual(self.results()[0]["action"], "promote")

    def test_caution_requires_and_records_explicit_approval(self):
        skill = self.backup()
        with patch.object(gate, "docker_scan", return_value=(0, report("CAUTION", 40, "MEDIUM"), "")), patch.object(gate, "confirm", return_value=True) as confirm:
            result = gate.review_backup(skill, self.stage, self.vault)
        self.assertIn("CAUTION risks", confirm.call_args.args[0])
        self.assertEqual(result["action"], "promote")
        self.assertEqual(result["scanner"]["risk_assessment"]["recommendation"], "CAUTION")
        self.assertEqual(result["policy"], "manual-caution")
        self.assertTrue(self.results()[0]["human_approved"])

    def test_decline_keeps_skill_inactive_and_original_intact(self):
        skill = self.backup()
        before = gate.fingerprint(skill.source)
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", return_value=False):
            result = gate.review_backup(skill, self.stage, self.vault)
        self.assertEqual(result["action"], "decline")
        self.assertFalse(result["human_approved"])
        self.assertFalse((self.vault / skill.source.name).exists())
        self.assertEqual(gate.fingerprint(skill.source), before)
        self.assertTrue(Path(result["snapshot"]).is_dir())

    def test_no_prompt_for_high_risk_errors_or_incomplete_scans(self):
        cases = [(0, report("DO_NOT_INSTALL", 80, "HIGH"), ""), (2, {}, "scanner unavailable")]
        incomplete = report("CAUTION", 10)
        incomplete["analysis_completeness"]["is_complete"] = False
        cases.append((0, incomplete, ""))
        for index, scan in enumerate(cases):
            with self.subTest(scan=scan):
                skill = self.backup(f"skill-{index}")
                with patch.object(gate, "docker_scan", return_value=scan), patch.object(gate, "confirm") as confirm:
                    result = gate.review_backup(skill, self.stage, self.vault)
                self.assertEqual(result["action"], "quarantine")
                confirm.assert_not_called()
                self.assertFalse((self.vault / skill.source.name).exists())

    def test_safe_only_option_blocks_caution_without_prompt(self):
        skill = self.backup()
        with patch.object(gate, "docker_scan", return_value=(0, report("CAUTION", 30, "MEDIUM"), "")), patch.object(gate, "confirm") as confirm:
            result = gate.review_backup(skill, self.stage, self.vault, allow_caution=False)
        self.assertEqual(result["action"], "quarantine")
        confirm.assert_not_called()

    def test_snapshot_modified_while_prompting_is_blocked(self):
        skill = self.backup()

        def tamper(question):
            payload = next((self.stage / "reviews").glob("*/payload/SKILL.md"))
            payload.write_text("changed while user was reading")
            return True

        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", side_effect=tamper):
            result = gate.review_backup(skill, self.stage, self.vault)
        self.assertEqual(result["action"], "quarantine")
        self.assertIn("TOCTOU", result["reason"])
        self.assertFalse((self.vault / skill.source.name).exists())

    def test_watchman_process_cannot_consume_interactive_review(self):
        skill = self.backup()

        def concurrent_processor(question):
            evidence = next((self.stage / "reviews").glob("*/scan.json"))
            self.assertEqual(json.loads(evidence.read_text())["scanner"]["risk_assessment"]["recommendation"], "SAFE")
            self.assertEqual(list((self.stage / "incoming").iterdir()), [])
            self.assertEqual(list((self.stage / "processing").iterdir()), [])
            self.assertEqual(gate.process(self.stage, self.vault), [])
            return False

        with patch.object(gate, "docker_scan", return_value=(0, report(), "")) as scan, patch.object(gate, "confirm", side_effect=concurrent_processor):
            gate.review_backup(skill, self.stage, self.vault)
        scan.assert_called_once()

    def test_interrupt_records_deferred_snapshot_and_never_installs(self):
        skill = self.backup()
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            gate.review_backup(skill, self.stage, self.vault)
        self.assertEqual(self.results()[0]["action"], "defer")
        self.assertEqual(gate.process(self.stage, self.vault), [])
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_invalid_name_or_contained_symlink_is_blocked_without_scanning(self):
        invalid = self.backup("Uppercase")
        linked = self.backup("with-link")
        (linked.source / "secret").symlink_to(self.base / "absent")
        with patch.object(gate, "docker_scan") as scan:
            for skill in (invalid, linked):
                result = gate.review_backup(skill, self.stage, self.vault)
                self.assertEqual(result["action"], "quarantine")
            scan.assert_not_called()

    def test_existing_vault_entry_is_never_overwritten_or_rescanned(self):
        skill = self.backup()
        installed = self.vault / skill.source.name
        installed.mkdir()
        (installed / "SKILL.md").write_text("existing")
        with patch.object(gate, "docker_scan") as scan:
            result = gate.review_backup(skill, self.stage, self.vault)
        self.assertEqual(result["action"], "skip")
        self.assertEqual((installed / "SKILL.md").read_text(), "existing")
        scan.assert_not_called()

    def test_discovery_finds_nested_skills_and_filters_agents(self):
        skill = self.backup(nested=".system")
        self.backup("other", agent="cursor")
        before = self.snapshot()
        found = review.discover_backups(self.vault, ("codex", "claude"))
        self.assertEqual(found, [skill])
        self.assertEqual(self.snapshot(), before)

    def test_discovery_does_not_follow_backup_symlinks(self):
        skill = self.backup()
        (skill.source.parent / "linked-skill").symlink_to(skill.source)
        (self.backups / "claude-linked-slot").symlink_to(skill.source.parent.parent)
        found = review.discover_backups(self.vault, ("codex", "claude"))
        self.assertEqual(found, [skill])
        self.assertIn("not followed", self.output.getvalue())

    def test_discovery_refuses_symlinked_backup_root(self):
        self.backups.parent.mkdir(parents=True)
        self.backups.symlink_to(self.base)
        with self.assertRaises(ValueError):
            review.discover_backups(self.vault, ("codex",))

    def test_interactive_commands_reject_piped_input_before_mutation(self):
        before = self.snapshot()
        with patch.object(sys.stdin, "isatty", return_value=False), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cli("setup"), 1)
            self.assertEqual(self.cli("review-backups"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_backup_review_cli_supports_existing_setup_and_safe_only(self):
        self.backup()
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report("CAUTION", 35, "MEDIUM"), "")), patch.object(gate, "confirm") as confirm:
            self.assertEqual(self.cli("review-backups", "--safe-only"), 1)
        confirm.assert_not_called()

    def test_setup_does_not_move_existing_skills_when_scanner_unavailable(self):
        original = self.home / ".agents" / "skills"
        original.mkdir(parents=True)
        (original / "keep").write_text("original")
        inode = original.stat().st_ino
        with patch.object(gate, "confirm", return_value=True), patch.object(gate, "scanner_ready", return_value=False), patch.object(gate, "setup_links") as links:
            self.assertEqual(self.cli("setup"), 1)
        self.assertEqual(original.stat().st_ino, inode)
        self.assertEqual((original / "keep").read_text(), "original")
        links.assert_not_called()

    def test_setup_can_cancel_before_any_filesystem_mutation(self):
        self.stage = self.home / "fresh-stage"
        self.vault = self.home / "fresh-vault"
        before = self.snapshot()
        with patch.object(gate, "confirm", return_value=False):
            self.assertEqual(self.cli("setup"), 0)
        self.assertEqual(self.snapshot(), before)

    def test_setup_does_not_link_if_real_scanner_selftest_fails(self):
        with patch.object(gate, "confirm", return_value=True), patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "scanner_self_test", return_value=False), patch.object(gate, "setup_links") as links:
            self.assertEqual(self.cli("setup"), 1)
        links.assert_not_called()

    def test_setup_full_flow_and_registration_needs_own_confirmation(self):
        source = self.home / ".agents" / "skills" / "demo-safe"
        source.mkdir(parents=True)
        (source / "SKILL.md").write_text("# Demo")
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "scanner_self_test", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report("CAUTION", 35, "MEDIUM"), "")), patch.object(gate, "confirm", side_effect=[True, True, False]), patch("builtins.input", return_value="1"), patch.object(gate, "register") as register:
            self.assertEqual(self.cli("setup"), 0)
        register.assert_not_called()
        self.assertTrue((self.home / ".agents" / "skills").is_symlink())
        self.assertTrue((self.vault / "demo-safe" / "SKILL.md").is_file())
        self.assertTrue(next(self.backups.glob("codex-*/skills/demo-safe/SKILL.md")).is_file())

    def test_setup_registers_only_after_affirmative_answer(self):
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "scanner_self_test", return_value=True), patch.object(gate, "confirm", side_effect=[True, True]), patch.object(gate, "register") as register, patch.object(gate, "process") as process:
            self.assertEqual(self.cli("setup"), 0)
        register.assert_called_once_with(self.stage, self.vault)
        process.assert_called_once_with(self.stage, self.vault)

    def test_doctor_is_read_only_and_reports_real_configuration(self):
        gate.setup_links(self.vault)
        expected = [sys.executable, str(Path(gate.__file__).resolve()), "--staging", str(self.stage), "--vault", str(self.vault), "process"]
        trigger = {"name": "agent-skill-gate", "command": expected, "expression": ["allof", ["name", "READY"], ["dirname", "incoming"], ["type", "f"]]}

        def probe(command, **kwargs):
            if "info" in command:
                return "test-runtime"
            if "inspect" in command:
                return "sha256:test-image"
            if "--version" in command:
                return "test-watchman"
            self.assertIn("--no-spawn", command)
            return json.dumps({"triggers": [trigger]})

        before = self.snapshot()
        with patch.object(gate, "probe", side_effect=probe), patch.object(gate, "docker_scan") as scan:
            self.assertEqual(self.cli("doctor"), 0)
        self.assertEqual(self.snapshot(), before)
        scan.assert_not_called()

    def test_doctor_fails_without_registered_trigger(self):
        gate.setup_links(self.vault)
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "probe", side_effect=["version", '{"triggers": []}']):
            self.assertEqual(self.cli("doctor"), 1)

    def test_missing_image_readiness_check_never_downloads_or_builds(self):
        with patch.object(gate, "probe", side_effect=["runtime", RuntimeError("No such image")]) as probe:
            self.assertFalse(gate.scanner_ready())
        self.assertEqual(len(probe.call_args_list), 2)
        self.assertIn("inspect", probe.call_args_list[1].args[0])

    def test_cannot_install_if_consent_event_cannot_be_written(self):
        skill = self.backup()
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", return_value=True), patch.object(gate, "audit", side_effect=OSError("log is not writable")), self.assertRaises(OSError):
            gate.review_backup(skill, self.stage, self.vault)
        self.assertFalse((self.vault / skill.source.name).exists())
        self.assertEqual(self.results()[0]["action"], "quarantine")

    def test_interrupt_after_install_does_not_claim_skill_is_inactive(self):
        skill = self.backup()
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch.object(gate, "confirm", return_value=True), patch.object(gate, "notify", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            gate.review_backup(skill, self.stage, self.vault)
        self.assertTrue((self.vault / skill.source.name).is_dir())
        self.assertEqual(self.results()[0]["action"], "promote")
        self.assertIn("after installation", self.results()[0]["reason"])

    def test_doctor_scan_exercises_scanner_without_installing(self):
        with patch.object(gate, "docker_scan", return_value=(0, report(), "")) as scan:
            self.assertTrue(gate.scanner_self_test())
        scan.assert_called_once()
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_docker_scan_contract_and_malformed_output(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps(report()), "")
        with patch.object(gate.subprocess, "run", return_value=completed) as run:
            self.assertEqual(gate.docker_scan(self.vault)[0], 0)
        command = run.call_args.args[0]
        for sequence in (("--pull", "never"), ("--network", "none"), ("--user", "65534:65534")):
            index = command.index(sequence[0])
            self.assertEqual(tuple(command[index:index + 2]), sequence)
        self.assertIn("--read-only", command)
        self.assertIn("--no-llm", command)
        self.assertIn("--fail-on-incomplete", command)
        for output in ("[]", "null", "invalid JSON"):
            with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                code, value, error = gate.docker_scan(self.vault)
            self.assertIsNotNone(review.scan_problem(code, value))

    def test_batch_scans_every_candidate_before_one_safe_group_choice(self):
        self.backup("first")
        self.backup("second")
        scans = []

        def scan(payload):
            scans.append(payload)
            self.assertEqual(list(self.vault.iterdir()), [])
            return 0, report(), ""

        def choose(message):
            self.assertEqual(len(scans), 2)
            self.assertEqual(list(self.vault.iterdir()), [])
            self.assertTrue(list((self.stage / "reports").glob("*-preview.md")))
            return "s"

        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", side_effect=scan), patch("builtins.input", side_effect=choose) as menu, patch.object(gate, "confirm") as confirm:
            self.assertEqual(self.cli("review-backups"), 0)
        menu.assert_called_once()
        confirm.assert_not_called()
        self.assertEqual(sorted(path.name for path in self.vault.iterdir()), ["first", "second"])
        self.assertTrue(all(result["approval_method"] == "safe-group" for result in self.results()))
        events = [json.loads(line) for line in (self.stage / "logs" / "events.jsonl").read_text().splitlines()]
        self.assertEqual(sum(event.get("event") == "safe-group-approved" for event in events), 1)
        self.assertTrue(list((self.home / "Downloads").glob("*.md")))

    def test_safe_group_never_approves_caution_implicitly(self):
        self.backup("safe")
        self.backup("caution")

        def scan(payload):
            # The original skill name is in the source metadata of the record;
            # distinguish fixtures by their copied manifest for this fake scan.
            if "caution" in (payload / "SKILL.md").read_text():
                return 0, report("CAUTION", 35, "MEDIUM"), ""
            return 0, report(), ""

        caution_source = self.backups / "codex-test-slot" / "skills" / "caution" / "SKILL.md"
        caution_source.write_text("# caution fixture")
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", side_effect=scan), patch("builtins.input", side_effect=["s", "n"]), patch.object(gate, "confirm") as confirm:
            self.assertEqual(self.cli("review-backups"), 0)
        confirm.assert_not_called()
        self.assertTrue((self.vault / "safe").is_dir())
        self.assertFalse((self.vault / "caution").exists())

    def test_selected_caution_requires_its_own_acceptance(self):
        self.backup("caution")
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report("CAUTION", 35, "MEDIUM"), "")), patch("builtins.input", return_value="1"), patch.object(gate, "confirm", return_value=False) as confirm:
            self.assertEqual(self.cli("review-backups"), 0)
        confirm.assert_called_once()
        self.assertIn("CAUTION risks", confirm.call_args.args[0])
        self.assertFalse((self.vault / "caution").exists())

    def test_snapshot_changed_during_batch_selection_cannot_be_installed(self):
        self.backup()

        def choose(message):
            payload = next((self.stage / "reviews").glob("*/payload/SKILL.md"))
            payload.write_text("changed after scan")
            return "s"

        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch("builtins.input", side_effect=choose):
            self.assertEqual(self.cli("review-backups"), 1)
        self.assertEqual(list(self.vault.iterdir()), [])
        self.assertIn("TOCTOU", self.results()[0]["reason"])

    def test_batch_cancel_exports_deferred_results_without_installing(self):
        self.backup()
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch("builtins.input", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cli("review-backups"), 130)
        self.assertEqual(self.results()[0]["action"], "defer")
        self.assertEqual(list(self.vault.iterdir()), [])
        self.assertTrue(list((self.home / "Downloads").glob("*.md")))

    def test_setup_skips_confirmation_for_existing_storage_links_and_watcher(self):
        gate.setup_links(self.vault)
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "scanner_self_test", return_value=True), patch.object(gate, "watchman_registered", return_value=True), patch.object(gate, "confirm") as confirm, patch.object(gate, "register") as register:
            self.assertEqual(self.cli("setup"), 0)
        confirm.assert_not_called()
        register.assert_not_called()
        self.assertIn("Nothing to migrate", self.output.getvalue())

    def test_duplicate_names_in_one_batch_never_overwrite_first_install(self):
        first = self.backup("demo", agent="claude")
        second = self.backup("demo", agent="codex")
        (first.source / "SKILL.md").write_text("# First version")
        (second.source / "SKILL.md").write_text("# Second version")
        with patch.object(gate, "scanner_ready", return_value=True), patch.object(gate, "docker_scan", return_value=(0, report(), "")), patch("builtins.input", return_value="s"):
            self.assertEqual(self.cli("review-backups"), 0)
        self.assertEqual((self.vault / "demo" / "SKILL.md").read_text(), "# First version")
        self.assertEqual(sorted(result["action"] for result in self.results()), ["promote", "skip"])


if __name__ == "__main__":
    unittest.main()
