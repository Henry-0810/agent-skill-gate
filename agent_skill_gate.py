#!/usr/bin/env python3
"""Fail-closed, Watchman-triggered skill pre-install gate (macOS/POSIX).

Only READY jobs are processed. The untrusted skill is NEVER executed by this tool.
It is analyzed by SkillSpector in a constrained Docker container.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

from agent_links import (
    DEFAULT_AGENTS, _directory, _locations, _overlap, _plans,
    parse_agents, setup_links, verify_links,
)
from agent_review import (
    BackupSkill, ReviewJob, confirm, discover_backups, parse_review_selection,
    report_parts, review_table, scan_problem, show_scan, visible,
)
from agent_dashboard import export_dashboard, load_review_reports, render_dashboard, write_markdown

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_FILES = 3000
MAX_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
SCANNER_TIMEOUT = 300


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def paths() -> tuple[Path, Path]:
    staging = (
        Path(os.environ.get("AGENT_GATE_STAGING", "~/.agent-staging"))
        .expanduser()
        .absolute()
    )
    vault = (
        Path(os.environ.get("AGENT_GATE_VAULT", "~/.local/share/agent-skills"))
        .expanduser()
        .absolute()
    )
    return staging, vault


def refuse_symlink_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing symlink as managed directory: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"Not a directory: {path}")


def initialize(stage: Path, vault: Path) -> None:
    for d in (stage, vault):
        refuse_symlink_directory(d)
        d.mkdir(parents=True, exist_ok=True)
    stage.chmod(0o700)
    for child in ("build", "incoming", "processing", "quarantine", "reports", "logs", "reviews"):
        p = stage / child
        refuse_symlink_directory(p)
        p.mkdir(mode=0o700, exist_ok=True)
    config = stage / ".watchmanconfig"
    expected = {
        "settle": 500,
        "ignore_dirs": ["build", "processing", "quarantine", "reports", "logs", "reviews"],
    }
    if not config.exists():
        config.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    print(f"Staging: {stage}\nVault:   {vault}")


def valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name)) and name not in {".", ".."}


def check_skill_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"Skill root must be a real directory: {root}")
    manifest = root / "SKILL.md"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError(f"Missing regular SKILL.md: {manifest}")


def copy_skill_snapshot(src: Path, dst: Path) -> None:
    """No symlinks, special files, VCS metadata or unbounded content.

    Uses O_NOFOLLOW for individual file opens. This does not isolate another
    hostile process with the same uid; see docs/SECURITY.md.
    """
    count = [0]
    total = [0]

    def visit(source: Path, target: Path, depth: int) -> None:
        if depth > 25:
            raise ValueError("Directory nesting exceeds 25 levels")
        before = os.lstat(source)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError(f"Expected directory: {source}")
        target.mkdir(mode=0o755)
        target.chmod(0o755)
        with os.scandir(source) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            if entry.name in {".git", ".hg", ".svn", "READY"}:
                raise ValueError(f"Unsupported control/VCS entry: {entry.path}")
            info = entry.stat(follow_symlinks=False)
            out = target / entry.name
            if stat.S_ISDIR(info.st_mode):
                visit(Path(entry.path), out, depth + 1)
            elif stat.S_ISREG(info.st_mode):
                count[0] += 1
                total[0] += info.st_size
                if (
                    count[0] > MAX_FILES
                    or total[0] > MAX_BYTES
                    or info.st_size > MAX_FILE_BYTES
                ):
                    raise ValueError("Skill exceeds file-count/byte limits")
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                )
                fd = os.open(entry.path, flags)
                try:
                    opened = os.fstat(fd)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_size > MAX_FILE_BYTES
                    ):
                        raise ValueError(
                            f"Changed or invalid source file: {entry.path}"
                        )
                    with os.fdopen(fd, "rb", closefd=False) as fin:
                        with out.open("xb") as fout:
                            copied = 0
                            while True:
                                chunk = fin.read(65536)
                                if not chunk:
                                    break
                                copied += len(chunk)
                                if (
                                    copied > MAX_FILE_BYTES
                                    or total[0] - info.st_size + copied > MAX_BYTES
                                ):
                                    raise ValueError(
                                        "File grew beyond byte limits during copy"
                                    )
                                fout.write(chunk)
                    out.chmod(0o755 if opened.st_mode & 0o111 else 0o644)
                finally:
                    os.close(fd)
            else:
                raise ValueError(f"Symlink or special file rejected: {entry.path}")

    visit(src, dst, 0)
    check_skill_root(dst)


def fingerprint(root: Path) -> str:
    """Digest the EXACT files that will be promoted. Reject links/special files."""
    check_skill_root(root)
    h = hashlib.sha256()
    nfiles = 0
    nbytes = 0
    for parent, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        for item in dirs + files:
            p = Path(parent) / item
            rel = p.relative_to(root).as_posix()
            st = os.lstat(p)
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise ValueError(f"Link/special entry after snapshot: {p}")
            h.update(rel.encode("utf-8", "surrogateescape") + b"\0")
            # Preserve mode changes in the verdict, since an executable bit can
            # influence scanner severity even when file content is identical.
            h.update(str(stat.S_IMODE(st.st_mode)).encode("ascii") + b"\0")
            if stat.S_ISREG(st.st_mode):
                nfiles += 1
                nbytes += st.st_size
                if (
                    nfiles > MAX_FILES
                    or nbytes > MAX_BYTES
                    or st.st_size > MAX_FILE_BYTES
                ):
                    raise ValueError("Snapshot changed beyond limits")
                h.update(b"F")
                fd = os.open(
                    p,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                )
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise ValueError(f"File changed during hashing: {p}")
                    with os.fdopen(fd, "rb", closefd=False) as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                finally:
                    os.close(fd)
            else:
                h.update(b"D")
    return h.hexdigest()


def submit(source: Path, stage: Path) -> Path:
    source = source.expanduser().absolute()
    build = (stage / "build").resolve(strict=True)
    # Do not let a source symlink escape the designated staging/build area.
    if not source.resolve(strict=True).is_relative_to(build):
        raise ValueError(f"Source must be inside {build}")
    if source.is_symlink() or not valid_name(source.name):
        raise ValueError(
            "Skill directory must be a non-symlink with a safe lowercase name"
        )
    check_skill_root(source)
    job_id = f"{source.name}--{uuid.uuid4().hex[:12]}"
    tmp = stage / "incoming" / f".tmp-{job_id}"
    dest = stage / "incoming" / job_id
    try:
        tmp.mkdir(mode=0o700)
        copy_skill_snapshot(source, tmp / "payload")
        (tmp / "name").write_text(source.name + "\n", encoding="utf-8")
        tmp.rename(dest)  # complete snapshot is moved atomically on the same filesystem
        # Publish READY only AFTER final job directory exists: Watchman sees one
        # final, atomic marker event and never scans a still-populating folder.
        marker_tmp = dest / ".READY.tmp"
        marker_tmp.write_text(utcnow() + "\n", encoding="utf-8")
        marker_tmp.rename(dest / "READY")
    except Exception:
        for partial in (tmp, dest):
            if partial.exists():
                shutil.rmtree(partial)
        raise
    print(f"Submitted {source.name} -> {dest}; Watchman will pick up READY")
    return dest


def docker_executable() -> str:
    # Watchman inherits its daemon's PATH, not the registering terminal's PATH.
    configured = os.environ.get("AGENT_GATE_DOCKER_BIN")
    if configured:
        return configured
    for path in (
        "/opt/homebrew/bin/docker",
        "/usr/local/bin/docker",
        "/usr/bin/docker",
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("docker") or "docker"


def docker_scan(payload: Path) -> tuple[int, dict, str]:
    image = os.environ.get("AGENT_GATE_SCANNER_IMAGE", "agent-skill-gate-scanner:local")
    cmd = [
        docker_executable(),
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--user",
        "65534:65534",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        "--mount",
        f"type=bind,source={payload},target=/scan,readonly",
        image,
        "scan",
        "/scan",
        "--no-llm",
        "--format",
        "json",
        "--fail-on-incomplete",
    ]
    try:
        completed = subprocess.run(
            cmd, text=True, capture_output=True, timeout=SCANNER_TIMEOUT, check=False
        )
        stdout = completed.stdout
        if len(stdout) > 8 * 1024 * 1024:
            return 2, {}, "Scanner JSON output exceeds 8 MiB"
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            report = {}
        if not isinstance(report, dict):
            return 2, {}, "Scanner JSON must be an object"
        return completed.returncode, report, completed.stderr[-4000:]
    except (OSError, subprocess.TimeoutExpired) as e:
        return 2, {}, str(e)


def notify(message: str) -> None:
    if sys.platform != "darwin":
        return

    def quote(value: str) -> str:
        return (
            '"'
            + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
            + '"'
        )

    apple_script = f"display notification {quote(message[:180])} with title {quote('Agent Skill Gate')}"
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            ["/usr/bin/osascript", "-e", apple_script],
            capture_output=True,
            timeout=5,
            check=False,
        )


def audit(stage: Path, result: dict) -> None:
    log = stage / "logs" / "events.jsonl"
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result, sort_keys=True) + "\n")


def scan_payload(payload: Path, result: dict) -> None:
    """Bind scanner evidence to a snapshot for both manual and automatic use."""
    check_skill_root(payload)
    result["sha256"] = fingerprint(payload)
    code, scan, stderr = docker_scan(payload)
    result.update({"scanner_exit": code, "scanner": scan, "scanner_error": stderr})
    if result["sha256"] != fingerprint(payload):
        raise ValueError("Skill snapshot changed during scanning; possible TOCTOU")


def promote_payload(payload: Path, vault: Path, name: str, expected_hash: str) -> None:
    if not valid_name(name):
        raise ValueError("Invalid skill name")
    # Also catches changes made while the user was reading the report/prompt.
    if fingerprint(payload) != expected_hash:
        raise ValueError("Skill snapshot changed before installation; possible TOCTOU")
    with _directory(vault):
        target = vault / name
        if os.path.lexists(target):
            raise ValueError(f"Refusing to replace installed skill: {target}")
        payload.rename(target)


def inspect_job(job: Path, stage: Path, vault: Path) -> dict:
    payload = job / "payload"
    result: dict = {"job": job.name, "time": utcnow(), "action": "quarantine"}
    decision = "blocked"
    try:
        skill_name = (job / "name").read_text(encoding="utf-8").strip()
        result["skill"] = skill_name
        if not valid_name(skill_name) or not job.name.startswith(skill_name + "--"):
            raise ValueError("Invalid job name or skill metadata")
        scan_payload(payload, result)
        problem = scan_problem(result["scanner_exit"], result["scanner"])
        if problem:
            raise ValueError(problem)
        promote_payload(payload, vault, skill_name, result["sha256"])
        result["action"] = "promote"
        decision = "installed"
        notify(f"Approved and installed: {skill_name}")
    except Exception as e:
        result["reason"] = str(e)
        quarantine = stage / "quarantine" / job.name
        if not quarantine.exists():
            job.rename(quarantine)
        notify(f"Blocked skill: {result.get('skill', job.name)}")
    finally:
        if decision == "installed":
            shutil.rmtree(job)
        report = stage / "reports" / f"{job.name}.json"
        try:
            with report.open("x", encoding="utf-8") as f:
                os.chmod(report, 0o600)
                json.dump(result, f, indent=2)
                f.write("\n")
        except FileExistsError:
            # A previous attempt must not have its audit overwritten.
            audit(
                stage,
                {"time": utcnow(), "warning": "report-already-exists", "job": job.name},
            )
        audit(stage, {k: v for k, v in result.items() if k != "scanner"})
        print(
            f"{job.name}: {result['action']} — {result.get('reason', 'SAFE')}",
            flush=True,
        )
    return result


def process(stage: Path, vault: Path) -> list[dict]:
    results = []
    lock = stage / ".processing.lock"
    with lock.open("a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        # Recover jobs left in processing by a prior crash (re-scan from scratch).
        for job in sorted((stage / "processing").iterdir()):
            if job.is_dir() and not job.is_symlink() and (job / "payload").is_dir():
                results.append(inspect_job(job, stage, vault))
        for job in sorted((stage / "incoming").iterdir()):
            if job.name.startswith(".tmp-") or job.is_symlink() or not job.is_dir():
                continue
            ready = job / "READY"
            if not ready.is_file() or ready.is_symlink():
                continue
            target = stage / "processing" / job.name
            if target.exists():
                continue
            job.rename(target)
            (target / "READY").unlink(missing_ok=True)
            results.append(inspect_job(target, stage, vault))
    return results


def watchman_json(command: list) -> dict:
    completed = subprocess.run(
        ["watchman", "-j"],
        input=json.dumps(command) + "\n",
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"Empty Watchman response: {completed.stderr}")
    response = json.loads(completed.stdout)
    if "error" in response:
        raise RuntimeError(f"Watchman: {response['error']}")
    return response


def register(stage: Path, vault: Path) -> None:
    response = watchman_json(["watch-project", str(stage)])
    watched = response.get("watch")
    if watched != str(stage):
        raise RuntimeError(f"Watchman unexpectedly watched {watched}, not {stage}")
    trigger = {
        "name": "agent-skill-gate",
        "expression": [
            "allof",
            ["name", "READY"],
            ["dirname", "incoming"],
            ["type", "f"],
        ],
        "command": [
            sys.executable,
            str(Path(__file__).resolve()),
            "--staging",
            str(stage),
            "--vault",
            str(vault),
            "process",
        ],
        "append_files": False,
        "stdin": "/dev/null",
    }
    watchman_json(["trigger", str(stage), trigger])
    print("Watchman trigger registered; processing any READY backlog now.")


def probe(command: list[str], *, input_text: str | None = None) -> str:
    completed = subprocess.run(
        command, input=input_text, capture_output=True, text=True,
        timeout=15, check=False,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr[-1000:] or f"Command exited {completed.returncode}")
    return completed.stdout.strip()


def scanner_ready() -> bool:
    """Local inspection only: never pull an image or install dependencies."""
    docker = docker_executable()
    try:
        version = probe([docker, "info", "--format", "{{.ServerVersion}}"])
        print(f"PASS Docker runtime: {visible(version)}")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL Docker runtime: {visible(exc)}")
        print("Start your Docker runtime and retry 'doctor'.")
        return False
    try:
        image = os.environ.get("AGENT_GATE_SCANNER_IMAGE", "agent-skill-gate-scanner:local")
        identity = probe([docker, "image", "inspect", image, "--format", "{{.Id}}"])
        if not identity.startswith("sha256:"):
            raise ValueError("Scanner image inspection did not return an image ID")
        print(f"PASS local scanner image: {visible(identity)}")
        return True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL local scanner image: {visible(exc)}")
        print("Build the scanner from an official commit you reviewed; see README:")
        print("  ./scripts/build-scanner.sh <REVIEWED_40_CHARACTER_COMMIT_SHA>")
        return False


def scanner_self_test() -> bool:
    """Exercise the real constrained scan command using harmless temporary input."""
    with tempfile.TemporaryDirectory(prefix="agent-gate-check-") as directory:
        payload = Path(directory).resolve() / "demo-safe"
        payload.mkdir(mode=0o755)
        (payload / "SKILL.md").write_text(
            "---\nname: demo-safe\ndescription: Summarize selected public documentation.\n"
            "---\n# Documentation helper\nRead selected public documentation and summarize it.\n",
            encoding="utf-8",
        )
        result = {"skill": "demo-safe"}
        scan_payload(payload, result)
        problem = scan_problem(result["scanner_exit"], result["scanner"])
        if problem:
            show_scan(result)
            print(f"FAIL scanner self-test: {visible(problem)}")
            return False
    print("PASS real scanner self-test; temporary input was never installed.")
    return True


def storage_ready(stage: Path, vault: Path) -> None:
    if _overlap(stage, vault):
        raise ValueError("Staging and approved vault must not overlap")
    _locations(vault, None)
    with _directory(stage):
        for name in ("build", "incoming", "processing", "quarantine", "reports", "logs"):
            with _directory(stage / name):
                pass


def doctor(stage: Path, vault: Path, agents: tuple[str, ...], *, scan: bool = False) -> int:
    """Read-only readiness checks; --scan additionally uses a temporary fixture."""
    failed = False
    try:
        storage_ready(stage, vault)
        print("PASS staging and vault layout")
    except (OSError, ValueError) as exc:
        print(f"FAIL storage: {visible(exc)}")
        failed = True
    failed |= bool(verify_links(vault, agents))
    scanner_ok = scanner_ready()
    failed |= not scanner_ok
    if scan and scanner_ok:
        try:
            failed |= not scanner_self_test()
        except (OSError, ValueError) as exc:
            print(f"FAIL scanner self-test: {visible(exc)}")
            failed = True
    try:
        version = probe(["watchman", "--version"])
        print(f"PASS Watchman CLI: {visible(version)}")
        # Do not start a daemon as a side effect of a readiness check.
        response = json.loads(probe(
            ["watchman", "--no-spawn", "-j"],
            input_text=json.dumps(["trigger-list", str(stage)]) + "\n",
        ))
        expected = [sys.executable, str(Path(__file__).resolve()), "--staging", str(stage), "--vault", str(vault), "process"]
        expression = ["allof", ["name", "READY"], ["dirname", "incoming"], ["type", "f"]]
        if not isinstance(response, dict) or not any(
            isinstance(trigger, dict) and trigger.get("name") == "agent-skill-gate"
            and trigger.get("command") == expected and trigger.get("expression") == expression
            for trigger in response.get("triggers", [])
        ):
            raise ValueError("No matching trigger for this script, staging directory and vault; run 'register'")
        print("PASS Watchman trigger configuration (event delivery still needs an end-to-end test)")
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL future automatic processing: {visible(exc)}")
        failed = True
    return int(failed)


def new_review(
    skill: BackupSkill, stage: Path, *, allow_caution: bool = True,
    run_id: str | None = None,
) -> ReviewJob:
    job = stage / "reviews" / f"review-{uuid.uuid4().hex}"
    result = {
        "job": job.name, "skill": skill.source.name, "source": str(skill.source),
        "agent": skill.agent, "time": utcnow(), "action": "pending",
        "human_approved": False, "policy": "manual-caution" if allow_caution else "manual-safe-only",
    }
    if run_id:
        result["run_id"] = run_id
    job.mkdir(mode=0o700)
    return ReviewJob(job, result)


def write_review_json(path: Path, result: dict) -> None:
    with path.open("x", encoding="utf-8") as file:
        os.chmod(path, 0o600)
        json.dump(result, file, indent=2)
        file.write("\n")


def finalize_review(review: ReviewJob, stage: Path, *, quiet: bool = False) -> None:
    if review.finalized:
        return
    job, result = review.path, review.result
    if result["action"] == "pending":
        result.update(action="defer", reason="Review interrupted or deferred before a decision")
    if result["action"] in {"quarantine", "decline"}:
        target = stage / "quarantine" / job.name
        if os.path.lexists(target):
            raise RuntimeError(f"Quarantine collision; review retained at {job}")
        job.rename(target)
        result["snapshot"] = str(target)
    elif result["action"] in {"promote", "skip"}:
        shutil.rmtree(job)
    else:
        result["snapshot"] = str(job)
    report = stage / "reports" / f"{job.name}.json"
    result["report_file"] = str(report)
    write_review_json(report, result)
    review.finalized = True
    audit(stage, {key: value for key, value in result.items() if key != "scanner"})
    if not quiet:
        print(f"{visible(result['skill'])}: {result['action']} — {visible(result.get('reason', 'installed after approval'))}")
        print(f"Report: {visible(report)}")


def prepare_review(review: ReviewJob, stage: Path, vault: Path, *, quiet: bool = False) -> None:
    """Collect evidence without installing or asking for approval."""
    job, result = review.path, review.result
    name, source = result["skill"], Path(result["source"])
    try:
        if not valid_name(name):
            raise ValueError("Skill directory name is not a safe lowercase installation name")
        if os.path.lexists(vault / name):
            result.update(action="skip", reason="Name already exists in vault; never replaced")
            return
        with _directory(source):
            copy_skill_snapshot(source, job / "payload")
        scan_payload(job / "payload", result)
        write_review_json(job / "scan.json", result)
        problem = scan_problem(
            result["scanner_exit"], result["scanner"],
            allow_caution=result["policy"] == "manual-caution",
        )
        if problem:
            raise ValueError(problem)
    except Exception as exc:
        result.update(action="quarantine", reason=str(exc))
    finally:
        if result["action"] != "pending":
            finalize_review(review, stage, quiet=quiet)


def apply_review(
    review: ReviewJob, stage: Path, vault: Path, approved: bool, *,
    method: str = "individual", quiet: bool = False,
) -> None:
    job, result = review.path, review.result
    name = result["skill"]
    if review.finalized or result["action"] != "pending":
        return
    try:
        if not approved:
            result.update(action="decline", reason="User declined; original backup preserved")
            return
        # A previously chosen row in this batch may have installed the same
        # name from another backup. Do not replace it or ask for false consent.
        if os.path.lexists(vault / name):
            result.update(action="skip", reason="Name already exists in vault; never replaced")
            return
        problem = scan_problem(result["scanner_exit"], result["scanner"], allow_caution=result["policy"] == "manual-caution")
        if problem:
            raise ValueError(problem)
        result["human_approved"] = True
        result["approved_at"] = utcnow()
        result["approval_method"] = method
        audit(stage, {
            "event": "human-approved", "time": result["approved_at"],
            "job": job.name, "skill": name, "sha256": result["sha256"],
            "recommendation": result["scanner"]["risk_assessment"]["recommendation"],
            "policy": result["policy"], "approval_method": method,
            "run_id": result.get("run_id"),
        })
        promote_payload(job / "payload", vault, name, result["sha256"])
        result["action"] = "promote"
        if not quiet:
            notify(f"Reviewed and installed: {name}")
    except KeyboardInterrupt:
        result["reason"] = (
            "Review interrupted after installation completed"
            if result["action"] == "promote"
            else "Review interrupted; snapshot retained outside the vault"
        )
        raise
    except Exception as exc:
        result.update(action="quarantine", reason=str(exc))
    finally:
        finalize_review(review, stage, quiet=quiet)


def review_backup(
    skill: BackupSkill, stage: Path, vault: Path, *, allow_caution: bool = True,
) -> dict:
    """Single-skill review API; the CLI uses the scan-first batch flow below."""
    review = new_review(skill, stage, allow_caution=allow_caution)
    try:
        prepare_review(review, stage, vault)
        if review.result["action"] == "pending":
            show_scan(review.result)
            print(f"Full scan report (before deciding): {visible(review.path / 'scan.json')}")
            name = review.result["skill"]
            caution = report_parts(review.result)[1].get("recommendation") == "CAUTION"
            question = f"Accept the reported CAUTION risks and install {name}?" if caution else f"Install scanned skill {name} into the approved vault?"
            apply_review(review, stage, vault, confirm(question))
    finally:
        finalize_review(review, stage)
    return review.result


def require_terminal() -> None:
    if not sys.stdin.isatty():
        raise ValueError("Interactive review requires a terminal; no piped approval or --yes mode is supported")


def review_backups(
    stage: Path, vault: Path, agents: tuple[str, ...], *,
    allow_caution: bool = True, check_scanner: bool = True,
    report_output: Path | None = None,
) -> int:
    require_terminal()
    storage_ready(stage, vault)
    candidates = discover_backups(vault, agents)
    if not candidates:
        print("No backed-up skill roots found for the selected agents; nothing to migrate.")
        return 0
    print(f"Found {len(candidates)} backup skill folders. Scanning first; nothing is installed yet.")
    print("Offline static checks. Originals stay untouched. Higher score = more estimated risk.")
    if check_scanner and not scanner_ready():
        return 1
    with _directory(stage / "reviews", create=True):
        pass
    run_id = f"backup-review-{uuid.uuid4().hex}"
    reviews: list[ReviewJob] = []
    export_failed = False
    try:
        for index, skill in enumerate(candidates, 1):
            print(f"  [{index}/{len(candidates)}] {visible(skill.source.name, 40)} ...", end=" ", flush=True)
            review = new_review(skill, stage, allow_caution=allow_caution, run_id=run_id)
            reviews.append(review)
            prepare_review(review, stage, vault, quiet=True)
            risk = report_parts(review.result)[1]
            label = {"skip": "already installed", "quarantine": "blocked"}.get(review.result["action"], risk.get("recommendation", "ready"))
            print(visible(label))
        records = [review.result for review in reviews]
        print(review_table(records))
        preview = write_markdown(stage / "reports" / f"{run_id}-preview.md", render_dashboard(records))
        print(f"Full findings dashboard: {visible(preview)}")
        if any(record["action"] == "pending" for record in records):
            print("\nChoose what to install:")
            print("  s       Install the listed SAFE recommendations together")
            print("  1,3,5   Install selected row numbers (CAUTION asks separately)")
            print("  v 3     View a row's findings and explanation")
            print("  n       Finish without installing remaining rows [default]")
        else:
            print("No eligible rows need an installation decision.")
        while any(review.result["action"] == "pending" for review in reviews):
            try:
                answer = input("\nYour choice [n]: ")
            except EOFError:
                answer = "n"
            try:
                action, indices = parse_review_selection(answer, records)
            except ValueError as exc:
                print(visible(exc))
                continue
            if action == "view":
                show_scan(records[indices[0]])
                continue
            if action == "finish":
                for review in reviews:
                    apply_review(review, stage, vault, False, quiet=True)
                break
            if action == "safe-group":
                # The menu action explicitly authorizes this concrete list.
                # CAUTION never enters the group and still needs risk consent.
                audit(stage, {"event": "safe-group-approved", "time": utcnow(), "run_id": run_id,
                              "jobs": [reviews[index].result["job"] for index in indices],
                              "skills": [reviews[index].result["skill"] for index in indices]})
            for index in indices:
                review = reviews[index]
                caution = report_parts(review.result)[1].get("recommendation") == "CAUTION"
                approved = True
                if caution:
                    show_scan(review.result)
                    approved = confirm(f"Accept the reported CAUTION risks and install {review.result['skill']}?")
                apply_review(review, stage, vault, approved, method=action, quiet=True)
                print(f"  {visible(review.result['skill'])}: " + {"promote": "installed", "skip": "existing name preserved", "decline": "not installed", "quarantine": "blocked"}.get(review.result["action"], review.result["action"]))
            if any(review.result["action"] == "pending" for review in reviews):
                print(review_table(records))
                print("Remaining rows marked Choose can still be selected; enter n to finish.")
    finally:
        try:
            for review in reviews:
                finalize_review(review, stage, quiet=True)
        finally:
            if reviews:
                try:
                    _, downloaded = export_dashboard([review.result for review in reviews], stage, output=report_output)
                    export_failed = downloaded is None
                except (OSError, ValueError, RuntimeError) as exc:
                    print(f"Dashboard export failed: {visible(exc)}. Per-skill JSON records remain in reports/.")
                    export_failed = True
    results = [review.result for review in reviews]
    print("\nReview complete: " + " | ".join(
        f"{sum(result['action'] == action for result in results)} {label}"
        for action, label in (("promote", "installed"), ("quarantine", "blocked"), ("skip", "existing"), ("decline", "declined"))
    ))
    print("Original backups are preserved.")
    return int(export_failed or any(result["action"] == "quarantine" for result in results))


def export_existing_reports(stage: Path, *, output: Path | None = None, run_id: str | None = None) -> int:
    with _directory(stage / "reports"):
        records, warnings = load_review_reports(stage, run_id=run_id)
    if not records:
        print("No matching backup review JSON records found. No skills were scanned or changed.")
        return 1
    print(f"Exporting {len(records)} saved backup review records; no rescanning or installation.")
    _, downloaded = export_dashboard(records, stage, output=output, warnings=warnings)
    for warning in warnings:
        print(f"Report warning: {visible(warning)}")
    return int(downloaded is None or bool(warnings))


def watchman_registered(stage: Path, vault: Path) -> bool:
    response = json.loads(probe(
        ["watchman", "--no-spawn", "-j"],
        input_text=json.dumps(["trigger-list", str(stage)]) + "\n",
    ))
    expected = [sys.executable, str(Path(__file__).resolve()), "--staging", str(stage), "--vault", str(vault), "process"]
    expression = ["allof", ["name", "READY"], ["dirname", "incoming"], ["type", "f"]]
    return isinstance(response, dict) and any(
        isinstance(trigger, dict) and trigger.get("name") == "agent-skill-gate"
        and trigger.get("command") == expected and trigger.get("expression") == expression
        for trigger in response.get("triggers", [])
    )


def guided_setup(
    stage: Path, vault: Path, agents: tuple[str, ...], *, allow_caution: bool = True,
    report_output: Path | None = None,
) -> int:
    require_terminal()
    print("\nAGENT SKILL GATE — SETUP\n" + "=" * 72)
    print("Check installation → review backup scans → choose installs → future submissions")
    print("\n[1/4] Installation checks\n" + "-" * 72)
    try:
        storage_ready(stage, vault)
        print("Storage already initialized; no changes needed.")
    except (OSError, ValueError):
        if _overlap(stage, vault):
            raise ValueError("Staging and approved vault must not overlap")
        for path in (stage, vault):
            with _directory(path, allow_missing=True):
                pass
        if not confirm(f"Create missing storage folders at {visible(stage)} and {visible(vault)}?"):
            return 0
        initialize(stage, vault)
    if not scanner_ready() or not scanner_self_test():
        print("Setup stopped before link migration: scanner is not ready. Existing skills were not moved.")
        return 1
    print("\n[2/4] Agent folders\n" + "-" * 72)
    _, _, destinations = _locations(vault, None)
    plans = _plans(vault, destinations, agents)
    if all(plan.kind == "linked" for plan in plans):
        print("Already linked: " + ", ".join(agents) + ". Nothing to migrate.")
    else:
        if setup_links(vault, agents, dry_run=True, quiet=True):
            return 1
        if not confirm("Apply these links and preserve existing folders in backups?"):
            return 0
        if setup_links(vault, agents, quiet=True):
            return 1
    if verify_links(vault, agents, quiet=True):
        return 1
    print("\n[3/4] Backup scan and installation choices\n" + "-" * 72)
    result = review_backups(stage, vault, agents, allow_caution=allow_caution, check_scanner=False, report_output=report_output)
    print("\n[4/4] Future submissions\n" + "-" * 72)
    try:
        registered = watchman_registered(stage, vault)
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError):
        registered = False
    if registered:
        print("Watchman is already configured; no changes needed.")
    elif confirm("Enable Watchman for future submissions and process pending READY jobs (SAFE-only)?"):
        register(stage, vault)
        process(stage, vault)
    else:
        print("Watchman setup skipped. Use 'register' when ready; 'process' also works manually.")
    print("Run 'doctor --scan' to check readiness. Verify actual Watchman event delivery with a demo submission.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Watchman + Docker SkillSpector pre-install gate"
    )
    parser.add_argument(
        "--staging", type=Path, help="Override staging root (also AGENT_GATE_STAGING)"
    )
    parser.add_argument(
        "--vault", type=Path, help="Override approved vault (also AGENT_GATE_VAULT)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create staging/vault folders and .watchmanconfig")
    commands.add_parser("register", help="Register Watchman READY trigger")
    commands.add_parser("process", help="Manually process all READY/pending jobs")
    commands.add_parser("status", help="Show counts and watch registration")
    commands.add_parser("unregister", help="Remove Watchman trigger")
    links = commands.add_parser(
        "setup-links",
        help="Back up existing skills directories and link agents to the vault",
    )
    links.add_argument(
        "--dry-run", action="store_true",
        help="Preview every operation without filesystem changes",
    )
    verify = commands.add_parser(
        "verify-links", help="Read-only verification of agent skill links"
    )
    setup = commands.add_parser("setup", help="Interactive setup, backup review and optional Watchman registration")
    review = commands.add_parser("review-backups", help="Scan backups, compare results and choose installations")
    export = commands.add_parser("export-report", help="Export saved backup scans to a Markdown dashboard without rescanning")
    export.add_argument("--output", type=Path, help="New .md output file (default: your Downloads folder)")
    export.add_argument("--run-id", help="Export only a specific review run (default: all saved backup review records)")
    check = commands.add_parser("doctor", help="Read-only storage, links, Docker image and Watchman readiness checks")
    check.add_argument("--scan", action="store_true", help="Also scan a harmless temporary fixture; never install it")
    for command in (setup, review):
        command.add_argument("--safe-only", action="store_true", help="Block CAUTION even during manual review (default: allow explicit per-skill approval)")
        command.add_argument("--report-output", type=Path, help="New .md dashboard file (default: your Downloads folder)")
    for command in (links, verify, setup, review, check):
        command.add_argument(
            "--agents", type=parse_agents, default=DEFAULT_AGENTS,
            help="Comma-separated agents: codex,claude (default); cursor is opt-in",
        )
    add = commands.add_parser(
        "submit", help="Snapshot and submit a skill under staging/build"
    )
    add.add_argument("source", type=Path)
    args = parser.parse_args()
    stage, vault = paths()
    if args.staging:
        stage = args.staging.expanduser().absolute()
    if args.vault:
        vault = args.vault.expanduser().absolute()
    try:
        if args.command == "setup-links":
            return setup_links(vault, args.agents, dry_run=args.dry_run)
        elif args.command == "verify-links":
            return verify_links(vault, args.agents)
        elif args.command == "setup":
            return guided_setup(stage, vault, args.agents, allow_caution=not args.safe_only, report_output=args.report_output)
        elif args.command == "review-backups":
            return review_backups(stage, vault, args.agents, allow_caution=not args.safe_only, report_output=args.report_output)
        elif args.command == "export-report":
            return export_existing_reports(stage, output=args.output, run_id=args.run_id)
        elif args.command == "doctor":
            return doctor(stage, vault, args.agents, scan=args.scan)
        elif args.command == "init":
            initialize(stage, vault)
        else:
            if not (stage / "incoming").is_dir() or not vault.is_dir():
                raise RuntimeError("Run 'init' first")
            if args.command == "submit":
                submit(args.source, stage)
            elif args.command == "process":
                process(stage, vault)
            elif args.command == "register":
                register(stage, vault)
                process(stage, vault)
            elif args.command == "unregister":
                print(watchman_json(["trigger-del", str(stage), "agent-skill-gate"]))
            elif args.command == "status":
                for label in ("incoming", "processing", "quarantine", "reports"):
                    print(f"{label}: {len(list((stage / label).iterdir()))}")
                try:
                    print(
                        json.dumps(
                            watchman_json(["trigger-list", str(stage)]), indent=2
                        )
                    )
                except (OSError, subprocess.SubprocessError, RuntimeError) as e:
                    print(f"Watchman status unavailable: {e}")
        return 0
    except KeyboardInterrupt:
        print("\nCancelled. Unapproved snapshots remain outside the vault.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
