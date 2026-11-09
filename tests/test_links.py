import contextlib
import errno
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_links as links
import agent_skill_gate as gate


class LinkTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        # macOS /var and /tmp may be system symlinks; use the physical test root.
        self.base = Path(directory.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir()
        self.vault = self.home / ".local" / "share" / "agent-skills"
        self.vault.mkdir(parents=True)
        self.stage = self.home / "stage"
        self.backups = self.home / ".local" / "state" / "agent-skill-gate" / "backups"
        self.codex = self.home / ".agents" / "skills"
        self.claude = self.home / ".claude" / "skills"
        self.cursor = self.home / ".cursor" / "skills"
        # Every API/CLI invocation in this class is confined to the fake home.
        home_patch = patch.object(Path, "home", return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def cli(self, *arguments):
        argv = ["agent_skill_gate.py", "--staging", str(self.stage), "--vault", str(self.vault), *arguments]
        with patch.object(sys, "argv", argv):
            return gate.main()

    def original(self, path=None):
        path = self.codex if path is None else path
        path.mkdir(parents=True)
        (path / "old-skill").mkdir()
        (path / "old-skill" / "SKILL.md").write_bytes(b"original\n\x00content")
        (path / "hidden").write_text("keep")
        (path / "external").symlink_to(self.base / "absent")
        path.chmod(0o750)
        return path.stat().st_ino

    def snapshot(self):
        """Record entries, modes, link text, file contents and mtimes (not atime)."""
        result = {}
        for parent, dirs, files in os.walk(self.base, followlinks=False):
            for name in dirs + files:
                path = Path(parent) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    content = os.readlink(path)
                elif stat.S_ISREG(info.st_mode):
                    content = path.read_bytes()
                else:
                    content = None
                result[str(path.relative_to(self.base))] = (info.st_ino, info.st_mode, info.st_mtime_ns, content)
        return result

    def assert_original(self, path, inode):
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o750)
        self.assertEqual((path / "old-skill" / "SKILL.md").read_bytes(), b"original\n\x00content")
        self.assertEqual((path / "hidden").read_text(), "keep")
        self.assertTrue((path / "external").is_symlink())

    def test_missing_paths_create_default_links_without_cursor(self):
        self.assertEqual(self.cli("setup-links"), 0)
        for path in (self.codex, self.claude):
            self.assertTrue(path.is_symlink())
            self.assertEqual(path.resolve(strict=True), self.vault)
        self.assertFalse(self.cursor.parent.exists())
        self.assertFalse(self.backups.exists())
        self.assertIn("SKIP cursor", self.output.getvalue())

    def test_real_directories_backed_up_separately_without_promotion(self):
        inodes = {"codex": self.original(), "claude": self.original(self.claude)}
        self.assertEqual(self.cli("setup-links"), 0)
        for agent, inode in inodes.items():
            slots = list(self.backups.glob(f"{agent}-*"))
            self.assertEqual(len(slots), 1)
            self.assertEqual(stat.S_IMODE(slots[0].stat().st_mode), 0o700)
            self.assert_original(slots[0] / "skills", inode)
        self.assertEqual(list(self.vault.iterdir()), [])
        self.assertIn("BACKUP codex", self.output.getvalue())

    def test_setup_twice_is_idempotent(self):
        self.original()
        self.assertEqual(self.cli("setup-links"), 0)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 0)
        self.assertEqual(self.snapshot(), before)

    def test_correct_relative_link_is_preserved(self):
        self.codex.parent.mkdir()
        self.codex.symlink_to("../.local/share/agent-skills")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links", "--agents", "codex"), 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.cli("verify-links", "--agents", "codex"), 0)

    def test_wrong_link_aborts_all_agents_before_any_mutation(self):
        self.original()
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.claude.parent.mkdir()
        self.claude.symlink_to(elsewhere)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("unexpected link", self.output.getvalue())

    def test_broken_link_is_not_replaced(self):
        self.codex.parent.mkdir()
        self.codex.symlink_to(self.base / "missing")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("broken/unresolvable", self.output.getvalue())

    def test_looping_link_is_not_replaced(self):
        self.codex.parent.mkdir()
        self.codex.symlink_to("skills")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_dry_run_with_directory_and_missing_parent_does_not_mutate(self):
        self.original()
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links", "--dry-run"), 0)
        self.assertEqual(self.snapshot(), before)
        output = self.output.getvalue()
        self.assertIn("WOULD BACKUP", output)
        self.assertIn("WOULD LINK codex", output)
        self.assertIn(f"WOULD MKDIR {self.claude.parent}", output)
        self.assertIn(str(self.backups), output)

    def test_dry_run_conflict_is_failure_without_mutation(self):
        self.codex.parent.mkdir()
        self.codex.write_text("file")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links", "--dry-run"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_failed_link_creation_restores_original_directory(self):
        inode = self.original()
        with patch.object(links.os, "symlink", side_effect=PermissionError("denied")):
            self.assertEqual(self.cli("setup-links"), 1)
        self.assert_original(self.codex, inode)
        self.assertFalse(self.claude.parent.exists())
        self.assertEqual(list(self.backups.iterdir()), [])
        self.assertIn("RESTORED codex", self.output.getvalue())

    def test_rollback_preserves_new_occupant_and_backup(self):
        inode = self.original()

        def occupy(target, name, *, dir_fd):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
            with os.fdopen(fd, "w") as file:
                file.write("new occupant")
            raise FileExistsError("occupied during link creation")

        with patch.object(links.os, "symlink", side_effect=occupy):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertEqual(self.codex.read_text(), "new occupant")
        saved = list(self.backups.glob("codex-*/skills"))
        self.assertEqual(len(saved), 1)
        self.assert_original(saved[0], inode)
        self.assertIn("could not restore safely", self.output.getvalue())

    def test_failed_missing_link_creation_leaves_no_skills_entry(self):
        with patch.object(links.os, "symlink", side_effect=PermissionError("denied")):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertFalse(os.path.lexists(self.codex))
        self.assertFalse(self.backups.exists())

    def test_backup_slot_collision_preserves_both_directories(self):
        inode = self.original()
        slot = self.backups / "collision"
        slot.mkdir(parents=True)
        (slot / "keep").write_text("previous backup")
        before = self.snapshot()
        with patch.object(links, "_backup_name", return_value="collision"):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertEqual(self.snapshot(), before)
        self.assert_original(self.codex, inode)

    def test_empty_backup_slot_collision_is_also_refused(self):
        self.original()
        (self.backups / "collision").mkdir(parents=True)
        before = self.snapshot()
        with patch.object(links, "_backup_name", return_value="collision"):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_dry_run_backup_slot_collision_is_reported_without_changes(self):
        self.original()
        (self.backups / "collision").mkdir(parents=True)
        before = self.snapshot()
        with patch.object(links, "_backup_name", return_value="collision"):
            self.assertEqual(self.cli("setup-links", "--dry-run"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_cross_device_backup_error_leaves_original_intact(self):
        inode = self.original()
        with patch.object(links.os, "rename", side_effect=OSError(errno.EXDEV, "different filesystem")):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assert_original(self.codex, inode)
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_regular_file_and_fifo_conflicts_are_preserved(self):
        self.codex.parent.mkdir()
        self.codex.write_text("preserve")
        self.claude.parent.mkdir()
        os.mkfifo(self.claude)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_parent_symlink_is_refused_even_when_target_is_real_directory(self):
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        (self.home / ".agents").symlink_to(elsewhere)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_broken_parent_symlink_is_refused(self):
        (self.home / ".agents").symlink_to(self.base / "absent")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_vault_symlink_is_refused(self):
        self.vault.rmdir()
        elsewhere = self.base / "vault"
        elsewhere.mkdir()
        self.vault.symlink_to(elsewhere)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_missing_vault_fails_read_only(self):
        self.vault.rmdir()
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links", "--dry-run"), 1)
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_vault_parent_symlink_is_refused(self):
        physical = self.base / "physical-local"
        (self.home / ".local").rename(physical)
        (self.home / ".local").symlink_to(physical)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_backup_parent_symlink_is_refused_before_any_agent_changes(self):
        self.original(self.claude)
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        (self.home / ".local" / "state").symlink_to(elsewhere)
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_non_directory_backup_path_is_refused(self):
        self.original()
        self.backups.parent.mkdir(parents=True)
        self.backups.write_text("keep")
        before = self.snapshot()
        self.assertEqual(self.cli("setup-links"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_overlapping_vault_and_backup_storage_is_refused(self):
        self.backups.mkdir(parents=True)
        before = self.snapshot()
        self.assertEqual(links.setup_links(self.backups), 1)
        self.assertEqual(self.snapshot(), before)

    def test_vault_in_agent_configuration_directory_is_refused(self):
        self.codex.mkdir(parents=True)
        before = self.snapshot()
        self.assertEqual(links.setup_links(self.codex), 1)
        self.assertEqual(self.snapshot(), before)

    def test_cursor_only_changes_when_explicitly_selected(self):
        self.original(self.cursor)
        cursor_before = self.cursor.lstat()
        self.assertEqual(self.cli("setup-links"), 0)
        self.assertEqual(self.cursor.lstat(), cursor_before)
        self.assertEqual(self.cli("setup-links", "--agents", "cursor"), 0)
        self.assertTrue(self.cursor.is_symlink())
        self.assertEqual(self.cli("verify-links", "--agents", "cursor"), 0)

    def test_agent_selection_does_not_touch_other_agents(self):
        self.assertEqual(self.cli("setup-links", "--agents", "claude"), 0)
        self.assertFalse(self.codex.parent.exists())
        self.assertFalse(self.cursor.parent.exists())
        self.assertEqual(self.cli("verify-links", "--agents", "claude"), 0)
        self.assertEqual(self.cli("verify-links"), 1)

    def test_verify_is_read_only_for_missing_and_correct_links(self):
        before = self.snapshot()
        self.assertEqual(self.cli("verify-links"), 1)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.cli("setup-links"), 0)
        before = self.snapshot()
        self.assertEqual(self.cli("verify-links"), 0)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("PASS codex", self.output.getvalue())
        self.assertIn("PASS claude", self.output.getvalue())

    def test_verify_rejects_real_directory(self):
        self.original()
        before = self.snapshot()
        self.assertEqual(self.cli("verify-links", "--agents", "codex"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_verify_rejects_unexpected_link(self):
        self.codex.parent.mkdir()
        self.codex.symlink_to(self.base)
        before = self.snapshot()
        self.assertEqual(self.cli("verify-links", "--agents", "codex"), 1)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_agent_selection_is_cli_error_without_changes(self):
        for selection in ("", "codex,", "other", "codex/../../other"):
            with self.subTest(selection=selection):
                before = self.snapshot()
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    self.cli("setup-links", "--agents", selection)
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(self.snapshot(), before)

    def test_destination_changed_after_preflight_is_not_replaced(self):
        original_apply = links._apply

        def replace(plan, vault, backup_root):
            plan.path.parent.mkdir(parents=True, exist_ok=True)
            plan.path.write_text("appeared after preflight")
            return original_apply(plan, vault, backup_root)

        with patch.object(links, "_apply", side_effect=replace):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertEqual(self.codex.read_text(), "appeared after preflight")

    def test_existing_cli_commands_still_dispatch_with_temporary_paths(self):
        inode = self.original()
        self.assertEqual(self.cli("init"), 0)
        self.assert_original(self.codex, inode)
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.cli("process"), 0)
        source = self.stage / "build" / "demo-safe"
        source.mkdir()
        (source / "SKILL.md").write_text("# Demo")
        self.assertEqual(self.cli("submit", str(source)), 0)
        with patch.object(gate, "watchman_json", return_value={"watch": str(self.stage)}), patch.object(gate, "process") as process:
            self.assertEqual(self.cli("register"), 0)
            process.assert_called_once_with(self.stage, self.vault)
        with patch.object(gate, "watchman_json", return_value={"triggers": []}):
            self.assertEqual(self.cli("status"), 0)
            self.assertEqual(self.cli("unregister"), 0)

    def test_real_cli_process_exit_codes_with_isolated_home(self):
        script = Path(gate.__file__).resolve()
        command = [sys.executable, "-B", str(script), "--staging", str(self.stage), "--vault", str(self.vault)]
        # No inherited user configuration: even a CLI regression stays in temp.
        environment = {"HOME": str(self.home)}
        for arguments, code in (
            (("verify-links",), 1),
            (("init",), 0),
            (("setup-links", "--dry-run"), 0),
            (("setup-links",), 0),
            (("verify-links",), 0),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    command + list(arguments), env=environment,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertTrue(self.codex.is_symlink())
        self.assertTrue(self.claude.is_symlink())
        self.assertFalse(self.cursor.parent.exists())

    def recovery_script(self, slot_name):
        readme = Path(gate.__file__).with_name("README.md").read_text()
        script = readme.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        return script.replace("codex-REPLACE-WITH-EXACT-BACKUP-ID", slot_name)

    def test_documented_recovery_restores_original_without_touching_vault(self):
        inode = self.original()
        self.assertEqual(self.cli("setup-links", "--agents", "codex"), 0)
        (self.vault / "approved.txt").write_text("keep approved")
        slot = next(self.backups.iterdir())
        with patch.dict(os.environ, {"AGENT_GATE_VAULT": str(self.vault)}):
            exec(compile(self.recovery_script(slot.name), "README recovery", "exec"), {})
        self.assert_original(self.codex, inode)
        self.assertEqual((self.vault / "approved.txt").read_text(), "keep approved")
        self.assertEqual(self.cli("verify-links", "--agents", "codex"), 1)

    def test_documented_recovery_refuses_changed_link_without_mutation(self):
        self.original()
        self.assertEqual(self.cli("setup-links", "--agents", "codex"), 0)
        slot = next(self.backups.iterdir())
        self.codex.unlink()
        self.codex.symlink_to(self.base)
        before = self.snapshot()
        with patch.dict(os.environ, {"AGENT_GATE_VAULT": str(self.vault)}), self.assertRaises(SystemExit):
            exec(compile(self.recovery_script(slot.name), "README recovery", "exec"), {})
        self.assertEqual(self.snapshot(), before)

    def test_source_changed_while_creating_backup_is_not_moved(self):
        inode = self.original()
        original_backup_name = links._backup_name
        moved = self.base / "original"

        def change(agent):
            self.codex.rename(moved)
            self.codex.symlink_to(self.base / "absent")
            return original_backup_name(agent)

        with patch.object(links, "_backup_name", side_effect=change):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertTrue(self.codex.is_symlink())
        self.assert_original(moved, inode)
        self.assertEqual(list(self.backups.glob("*/skills")), [])

    def test_failed_restore_retains_backup_and_removes_only_own_reservation(self):
        inode = self.original()
        rename = links.os.rename
        calls = []

        def fail_restore(source, destination, **kwargs):
            calls.append((source, destination))
            if len(calls) == 2:
                raise PermissionError("restore denied")
            return rename(source, destination, **kwargs)

        with patch.object(links.os, "symlink", side_effect=PermissionError("link denied")), patch.object(links.os, "rename", side_effect=fail_restore):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        saved = list(self.backups.glob("codex-*/skills"))
        self.assertEqual(len(saved), 1)
        self.assert_original(saved[0], inode)
        self.assertFalse(os.path.lexists(self.codex))
        self.assertIn("could not restore safely", self.output.getvalue())

    def test_case_alias_vault_inside_source_is_refused(self):
        self.original()
        nested = self.codex / "nested-vault"
        nested.mkdir()
        alias = self.home / ".AGENTS" / "skills" / "nested-vault"
        if not alias.exists():
            self.skipTest("requires a case-insensitive filesystem")
        before = self.snapshot()
        self.assertEqual(links.setup_links(alias, ("codex",)), 1)
        self.assertEqual(self.snapshot(), before)

    def test_correct_links_verify_with_case_alias_vault(self):
        alias = self.home / ".LOCAL" / "share" / "agent-skills"
        if not alias.exists():
            self.skipTest("requires a case-insensitive filesystem")
        self.assertEqual(self.cli("setup-links"), 0)
        before = self.snapshot()
        self.assertEqual(links.verify_links(alias), 0)
        self.assertEqual(self.snapshot(), before)

    def test_case_alias_backup_overlap_is_refused(self):
        self.backups.mkdir(parents=True)
        alias = self.home / ".LOCAL" / "state" / "agent-skill-gate"
        if not alias.exists():
            self.skipTest("requires a case-insensitive filesystem")
        before = self.snapshot()
        self.assertEqual(links.setup_links(alias), 1)
        self.assertEqual(self.snapshot(), before)

    def test_partial_setup_is_safe_to_retry_after_later_agent_failure(self):
        inode = self.original(self.claude)
        symlink = links.os.symlink

        def fail_claude(target, name, *, dir_fd):
            if os.path.samestat(os.fstat(dir_fd), self.claude.parent.stat()):
                raise PermissionError("claude link denied")
            return symlink(target, name, dir_fd=dir_fd)

        with patch.object(links.os, "symlink", side_effect=fail_claude):
            self.assertEqual(self.cli("setup-links"), 1)
        self.assertTrue(self.codex.is_symlink())
        codex_inode = self.codex.lstat().st_ino
        self.assert_original(self.claude, inode)
        self.assertEqual(self.cli("setup-links"), 0)
        self.assertEqual(self.codex.lstat().st_ino, codex_inode)
        self.assertEqual(self.cli("verify-links"), 0)

    def test_environment_vault_configuration_is_honored(self):
        with patch.dict(os.environ, {"AGENT_GATE_VAULT": str(self.vault), "AGENT_GATE_STAGING": str(self.stage)}):
            with patch.object(sys, "argv", ["agent_skill_gate.py", "setup-links"]):
                self.assertEqual(gate.main(), 0)
        self.assertEqual(self.codex.resolve(strict=True), self.vault)
        self.assertFalse(self.stage.exists())

    def test_parent_replaced_by_symlink_after_preflight_is_not_followed(self):
        inode = self.original()
        original_apply = links._apply
        saved = self.base / "saved-agent-parent"
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()

        def replace(plan, vault, backup_root):
            plan.path.parent.rename(saved)
            plan.path.parent.symlink_to(elsewhere)
            return original_apply(plan, vault, backup_root)

        with patch.object(links, "_apply", side_effect=replace):
            self.assertEqual(self.cli("setup-links", "--agents", "codex"), 1)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assert_original(saved / "skills", inode)


if __name__ == "__main__":
    unittest.main()
