"""Scanner report policy, literal terminal output, and backup discovery.

Reports are untrusted input too: never interpret their text as terminal control
sequences or use a risk score as a probability or a guarantee of safety.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import shutil
import stat
import textwrap
import unicodedata

from agent_links import _directory, _entry, _locations


def visible(value: object, limit: int = 500) -> str:
    text = str(value)
    text = "".join(
        char if not unicodedata.category(char).startswith("C") else ascii(char)[1:-1]
        for char in text[:limit]
    )
    return text + ("..." if len(str(value)) > limit else "")


def scan_problem(code: int, report: object, *, allow_caution: bool = False) -> str | None:
    """One policy for unattended installs and interactive backup review.

    Older pinned scanners may omit completeness metadata. Their exit status
    under --fail-on-incomplete remains required. Explicit incomplete metadata
    always blocks, even when a report claims SAFE and the process exits zero.
    """
    if not isinstance(report, dict):
        return "Scanner did not return a JSON object"
    risk = report.get("risk_assessment")
    if not isinstance(risk, dict):
        return "Missing scanner risk assessment"
    score = risk.get("score")
    if (
        isinstance(score, bool) or not isinstance(score, (int, float))
        or not math.isfinite(score) or not 0 <= score <= 100
    ):
        return "Missing or invalid scanner risk score (expected 0-100)"
    completeness = report.get("analysis_completeness")
    if "analysis_completeness" in report:
        if not isinstance(completeness, dict) or completeness.get("is_complete") is not True:
            return "Scanner analysis is incomplete or completeness metadata is invalid"
        if completeness.get("execution_successful", True) is not True:
            return "Scanner reported unsuccessful analysis"
    if code != 0:
        return f"Scanner did not complete successfully: exit={code}"
    metadata = report.get("metadata", {})
    if not isinstance(metadata, dict):
        return "Invalid scanner metadata"
    if metadata.get("execution_successful", True) is not True:
        return "Scanner reported unsuccessful execution"
    if report.get("execution_successful", True) is not True:
        return "Scanner reported unsuccessful execution"
    severity = risk.get("severity")
    if not isinstance(severity, str) or severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "Invalid scanner severity"
    if severity in {"HIGH", "CRITICAL"} or score > 50:
        return "High or critical overall risk is blocked"
    recommendation = risk.get("recommendation")
    allowed = {"SAFE", "CAUTION"} if allow_caution else {"SAFE"}
    if not isinstance(recommendation, str) or recommendation not in allowed:
        return f"Recommendation {visible(recommendation)} is blocked by installation policy"
    issues = report.get("issues")
    if not isinstance(issues, list) or any(not isinstance(issue, dict) for issue in issues):
        return "Invalid scanner findings"
    return None


def report_parts(result: dict) -> tuple[dict, dict, dict, list[dict]]:
    raw = result.get("scanner")
    report = raw if isinstance(raw, dict) else {}
    risk = report.get("risk_assessment")
    risk = risk if isinstance(risk, dict) else {}
    complete = report.get("analysis_completeness")
    complete = complete if isinstance(complete, dict) else {}
    issues = report.get("issues")
    issues = [issue for issue in issues if isinstance(issue, dict)] if isinstance(issues, list) else []
    return report, risk, complete, issues


def finding_text(issue: dict) -> str:
    for key in ("message", "finding", "title", "description", "explanation"):
        if isinstance(issue.get(key), str) and issue[key].strip():
            return issue[key]
    return str(issue.get("id", "No explanation provided"))


def show_scan(result: dict) -> None:
    report, risk, _, _ = report_parts(result)
    print("\n" + "-" * 72)
    print(f"Skill: {visible(result['skill'])}")
    print(f"Risk score: {visible(risk.get('score', 'not reported'))}/100 (higher = more risk)")
    print(f"Severity: {visible(risk.get('severity', 'not reported'))}")
    print(f"Recommendation: {visible(risk.get('recommendation', 'not reported'))}")
    print("Scan mode: offline static checks; no LLM analysis or live vulnerability lookups.")
    print("A low score is not a safety guarantee. Finding text is untrusted scanner output.")
    completeness = report.get("analysis_completeness")
    if isinstance(completeness, dict):
        print(f"Analysis complete: {visible(completeness.get('is_complete', 'not reported'))}")
        coverage = completeness.get("coverage_percent")
        print(f"Coverage: {visible(coverage)}%" if coverage is not None else "Coverage: not reported")
    else:
        print("Coverage metadata: not reported by this scanner version; strict exit policy still applies.")
    issues = report.get("issues")
    if isinstance(issues, list):
        print(f"Findings: {len(issues)}")
        for issue in issues[:10]:
            if not isinstance(issue, dict):
                continue
            location = issue.get("location")
            location = location if isinstance(location, dict) else {}
            where = f"{location.get('file', '?')}:{location.get('start_line', '?')}"
            print(f"  [{visible(issue.get('severity', '?'))}] {visible(where)}")
            print(f"    {visible(finding_text(issue))}")
            if issue.get("explanation") and issue["explanation"] != finding_text(issue):
                print(textwrap.fill(visible(issue['explanation'], 1600), width=88, initial_indent="    ", subsequent_indent="    "))
            if issue.get("remediation"):
                print(textwrap.fill("Suggested fix: " + visible(issue['remediation'], 1600), width=88, initial_indent="    ", subsequent_indent="    "))
        if len(issues) > 10:
            print("  Additional findings are in the full JSON report.")
    else:
        print("Findings: not reported")
    if result.get("scanner_error"):
        print(f"Scanner diagnostic: {visible(result['scanner_error'])}")
    if result.get("reason"):
        print(f"Decision note: {visible(result['reason'])}")


def review_table(records: list[dict]) -> str:
    lines = ["", "BACKUP SCAN RESULTS", "-" * 88]
    narrow = shutil.get_terminal_size(fallback=(100, 24)).columns < 100
    if not narrow:
        lines.append(f"{'#':>3}  {'Skill':24} {'Agent':6} {'Verdict':12} {'Risk':>4} {'Cover':>6} {'Issues':>6} {'Highest':8} Decision")
    for index, record in enumerate(records, 1):
        _, risk, complete, issues = report_parts(record)
        coverage = complete.get("coverage_percent")
        coverage = f"{coverage:g}%" if type(coverage) in (int, float) else "?"
        score = risk.get("score", "?")
        highest = next((level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if any(issue.get("severity") == level for issue in issues)), "none")
        decision = {"pending": "Choose", "promote": "Installed", "quarantine": "BLOCKED", "skip": "Existing", "decline": "Declined", "defer": "Deferred"}.get(record.get("action"), "Unknown")
        if complete.get("is_complete") is False:
            decision = "INCOMPLETE"
        name = visible(record.get("skill", "?"), 24)
        verdict = visible(risk.get("recommendation", "not scanned"), 12)
        count = str(len(issues)) if isinstance(record.get("scanner"), dict) else "?"
        if narrow:
            lines += [f"{index:>3}. {name} ({visible(record.get('agent', '?'))}) — {verdict}, risk {visible(score)}/100",
                      f"     Coverage {coverage} | findings {count}, highest {highest} | {decision}"]
        else:
            lines.append(f"{index:>3}  {name:24} {visible(record.get('agent', '?')):6} {verdict:12} {visible(score):>4} {coverage:>6} {count:>6} {highest:8} {decision}")
    lines += ["-" * 88,
              "SAFE is the overall rating; it can still contain HIGH findings.",
              "INCOMPLETE means coverage was limited. Those rows cannot be installed."]
    return "\n".join(lines)


def parse_review_selection(value: str, records: list[dict]) -> tuple[str, list[int]]:
    value = value.strip().lower()
    if value in {"", "n", "no", "q", "quit"}:
        return "finish", []
    if value.startswith("v "):
        number = value[2:].strip()
        if not number.isdecimal() or not 1 <= int(number) <= len(records):
            raise ValueError("Use v followed by one row number, for example: v 3")
        return "view", [int(number) - 1]
    if value in {"s", "safe"}:
        selected = [index for index, record in enumerate(records)
                    if record.get("action") == "pending" and report_parts(record)[1].get("recommendation") == "SAFE"]
        if not selected:
            raise ValueError("No SAFE rows are waiting for a decision")
        return "safe-group", selected
    numbers = value.split(",")
    if not numbers or len(numbers) > 3000 or any(not number.strip().isdecimal() for number in numbers):
        raise ValueError("Enter s, row numbers such as 1,3,5, v 3 for details, or n to finish")
    selected = list(dict.fromkeys(int(number.strip()) - 1 for number in numbers))
    if any(not 0 <= index < len(records) or records[index].get("action") != "pending" for index in selected):
        raise ValueError("Select only numbered rows marked Choose; blocked and existing rows cannot be installed")
    return "selected", selected


@dataclass
class ReviewJob:
    path: Path
    result: dict
    finalized: bool = False


def confirm(message: str) -> bool:
    """Default No, never infer approval from EOF, and let Ctrl-C abort."""
    while True:
        try:
            answer = input(message + " [y/N] ").strip().lower()
        except EOFError:
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False
        print("Enter y or n; pressing Enter means no.")


@dataclass(frozen=True)
class BackupSkill:
    agent: str
    source: Path


def discover_backups(vault: Path, agents: tuple[str, ...]) -> list[BackupSkill]:
    """Find skill roots, including nested categories, without following links.

    The backup is only inventoried; its contents and permissions never change.
    Stop descending when a SKILL.md is found: its subtree is one scan unit.
    """
    _, backup_root, _ = _locations(vault, None)
    found = []
    visited = 0

    def visit(path: Path, agent: str, depth: int) -> None:
        nonlocal visited
        visited += 1
        if visited > 3000 or depth > 25:
            raise ValueError("Backup discovery exceeds 3000 directories or 25 levels; review a smaller collection manually")
        with _directory(path) as (fd, _):
            manifest = _entry(fd, "SKILL.md")
            if manifest is not None:
                # A malformed manifest is a review candidate too: snapshot
                # validation will block it and record the reason in a report.
                found.append(BackupSkill(agent, path))
                return
            with os.scandir(fd) as entries:
                children = []
                for entry in entries:
                    if len(children) >= 3000:
                        raise ValueError("Too many entries in backup directory")
                    children.append((entry.name, entry.stat(follow_symlinks=False).st_mode))
            for name, mode in sorted(children):
                child = path / name
                if stat.S_ISLNK(mode):
                    print(f"SKIP backup symlink (not followed): {visible(child)}")
                elif stat.S_ISDIR(mode) and name not in {".git", ".hg", ".svn"}:
                    visit(child, agent, depth + 1)

    with _directory(backup_root, allow_missing=True) as (fd, _):
        if fd is None:
            return []
        with os.scandir(fd) as entries:
            slots = []
            for entry in entries:
                if len(slots) >= 3000:
                    raise ValueError("Too many backup slots; review a smaller collection manually")
                slots.append((entry.name, entry.stat(follow_symlinks=False).st_mode))
        for name, mode in sorted(slots):
            agent = next((agent for agent in agents if name.startswith(agent + "-")), None)
            if agent is None:
                continue
            if not stat.S_ISDIR(mode):
                print(f"SKIP unexpected backup slot: {visible(backup_root / name)}")
                continue
            slot = backup_root / name
            with _directory(slot) as (slot_fd, _):
                saved = _entry(slot_fd, "skills")
                if saved is None:
                    continue
                if not stat.S_ISDIR(saved.st_mode):
                    print(f"SKIP non-directory backup: {visible(slot / 'skills')}")
                    continue
            visit(slot / "skills", agent, 0)
    return found
