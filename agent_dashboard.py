"""Portable Markdown dashboards for saved backup review records.

Exporting reads reports, never skill contents, and never grants approval. The
Downloads resolver is portable; the scanner/Watchman gate remains POSIX-only.
"""

from __future__ import annotations

from collections import Counter
import datetime as dt
import html
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import uuid

from agent_review import finding_text, report_parts, visible


def _windows_downloads() -> Path:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    folder = GUID.from_buffer_copy(uuid.UUID("374de290-123f-4565-9164-39c4925e467b").bytes_le)
    value = ctypes.c_wchar_p()
    function = ctypes.windll.shell32.SHGetKnownFolderPath
    function.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
    function.restype = ctypes.c_long
    if function(ctypes.byref(folder), 0, None, ctypes.byref(value)) != 0:
        raise OSError("Windows Downloads Known Folder lookup failed")
    try:
        if not value.value:
            raise OSError("Windows did not return a Downloads directory")
        return Path(value.value)
    finally:
        free = ctypes.windll.ole32.CoTaskMemFree
        free.argtypes = [ctypes.c_void_p]
        free(ctypes.cast(value, ctypes.c_void_p))


def downloads_directory() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        try:
            return _windows_downloads()
        except (OSError, AttributeError):
            return home / "Downloads"
    if sys.platform != "darwin":
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        if not config_home.is_absolute():
            config_home = home / ".config"
        config = config_home / "user-dirs.dirs"
        try:
            if config.stat().st_size <= 65536:
                for line in config.read_text(encoding="utf-8").splitlines():
                    key, separator, raw = line.partition("=")
                    if separator and key.strip() == "XDG_DOWNLOAD_DIR":
                        tokens = shlex.split(raw, comments=True)
                        if len(tokens) != 1:
                            break
                        value = tokens[0]
                        for prefix in ("$HOME", "${HOME}"):
                            if value == prefix or value.startswith(prefix + "/"):
                                value = str(home) + value[len(prefix):]
                                break
                        # Read the setting as data; never source shell code.
                        if any(char in value for char in ("$", "`", "\0", "\n", "\r")):
                            break
                        candidate = Path(value)
                        if candidate.is_absolute():
                            return candidate
        except (OSError, UnicodeError, ValueError):
            pass
    return home / "Downloads"


def markdown_text(value: object, limit: int = 4000) -> str:
    text = html.escape(visible(value, limit), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>])", r"\\\1", text)


def _number(value: object, suffix: str = "") -> str:
    if type(value) in (int, float) and math.isfinite(value):
        return f"{value:g}{suffix}"
    return "unreported"


def outcome(result: dict) -> str:
    return {
        "promote": "Installed after approval", "quarantine": "Blocked",
        "decline": "Not installed (declined)", "skip": "Existing name (not rescanned)",
        "pending": "Awaiting decision", "defer": "Deferred / cancelled",
    }.get(result.get("action"), "Unknown outcome")


def render_dashboard(records: list[dict], *, title: str = "Backup skill scan dashboard", warnings: list[str] | None = None) -> str:
    actions = Counter(record.get("action", "unknown") for record in records)
    scanned = sum(isinstance(record.get("scanner"), dict) for record in records)
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# {markdown_text(title)}", "", f"Generated: {generated}", "",
        "Scope: saved scans of skills from the backup area. Originals are preserved.",
        "These are recorded decisions, not a live audit of the approved vault.", "",
        "## At a glance", "",
        "| Backup records | Distinct skill names | Scanned records | Installed | Blocked | Skipped | Declined | Awaiting / deferred |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
        f"| {len(records)} | {len({str(row.get('skill', '?')) for row in records})} | {scanned} | {actions['promote']} | {actions['quarantine']} | {actions['skip']} | {actions['decline']} | {actions['pending'] + actions['defer']} |", "",
        "Risk scores run from 0 to 100; higher means more estimated risk, not a probability of compromise.",
        "Overall SAFE can still contain HIGH-severity findings. Read the findings and coverage before accepting a skill.",
        "Scans use offline static checks: no LLM semantic analysis or live vulnerability lookups.",
        "Incomplete analysis is a coverage limitation, not proof of malicious behavior; installation remains blocked.", "",
        "## Results", "",
        "| # | Skill | Agent | Recommendation | Risk / 100 | Coverage | Findings | Highest finding | Recorded decision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for index, result in enumerate(records, 1):
        _, risk, completeness, issues = report_parts(result)
        highest = highest_finding(issues)
        lines.append(
            f"| {index} | [{markdown_text(result.get('skill', '?'))}](#skill-{index}) | "
            f"{markdown_text(result.get('agent', '?'))} | {markdown_text(risk.get('recommendation', 'unreported'))} | "
            f"{_number(risk.get('score'))} | {_number(completeness.get('coverage_percent'), '%')} | "
            f"{len(issues) if isinstance(result.get('scanner'), dict) else 'unreported'} | {highest} | {outcome(result)} |"
        )
    if warnings:
        lines += ["", "## Report loading warnings", ""]
        lines += [f"- {markdown_text(warning)}" for warning in warnings]
    lines += ["", "## Per-skill findings", ""]
    for index, result in enumerate(records, 1):
        report, risk, completeness, issues = report_parts(result)
        lines += [
            f"### Skill {index}", "", f"**{markdown_text(result.get('skill', '?'))}**", "",
            f"- Agent: {markdown_text(result.get('agent', '?'))}",
            f"- Decision: {outcome(result)}",
            f"- Overall recommendation: {markdown_text(risk.get('recommendation', 'unreported'))}; risk: {_number(risk.get('score'))}/100; severity: {markdown_text(risk.get('severity', 'unreported'))}",
            f"- Analysis complete: {markdown_text(completeness.get('is_complete', 'unreported'))}; coverage: {_number(completeness.get('coverage_percent'), '%')}",
            f"- Backup source: {markdown_text(result.get('source', 'unreported'))}",
            f"- Scan time: {markdown_text(result.get('time', 'unreported'))}",
            f"- Snapshot SHA-256: {markdown_text(result.get('sha256', 'unreported'))}",
            f"- JSON record: {markdown_text(result.get('report_file', result.get('job', 'unreported')))}",
            f"- Approval: {'recorded' if result.get('human_approved') else 'not recorded'}; method: {markdown_text(result.get('approval_method', 'individual' if result.get('human_approved') else 'none'))}",
        ]
        if result.get("reason"):
            lines.append(f"- Reason: {markdown_text(result['reason'])}")
        if result.get("scanner_error"):
            lines.append(f"- Scanner diagnostic: {markdown_text(result['scanner_error'])}")
        lines.append("")
        if not isinstance(result.get("scanner"), dict):
            lines += ["No scan result was recorded for this entry. A skipped existing name is not a clean verdict.", ""]
            continue
        raw_issues = report.get("issues")
        if not isinstance(raw_issues, list) or any(not isinstance(issue, dict) for issue in raw_issues):
            lines += ["Findings could not be read from this report; consult its JSON record and recorded reason.", ""]
        elif not issues:
            lines += ["No findings reported. This is not a guarantee of safe execution.", ""]
        for finding in issues[:100]:
            location = finding.get("location")
            location = location if isinstance(location, dict) else {}
            identifier = finding.get("id", finding.get("finding_id", "unreported"))
            lines += [
                f"#### {markdown_text(identifier)} — {markdown_text(finding.get('severity', 'unreported'))}", "",
                f"Location: {markdown_text(location.get('file', '?'))}:{markdown_text(location.get('start_line', '?'))}", "",
                markdown_text(finding_text(finding)), "",
            ]
            explanation = finding.get("explanation")
            if explanation and explanation != finding_text(finding):
                lines += [f"Explanation: {markdown_text(explanation)}", ""]
            if finding.get("remediation"):
                lines += [f"Suggested fix: {markdown_text(finding['remediation'])}", ""]
        if len(issues) > 100:
            lines += ["Only the first 100 findings are shown; the JSON record contains the full report.", ""]
    return "\n".join(lines) + "\n"


def highest_finding(issues: list[dict]) -> str:
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if any(issue.get("severity") == severity for issue in issues):
            return severity
    return "none" if not issues else "unreported"


def write_markdown(path: Path, content: str) -> Path:
    """Create a new report only. Existing files/links are never overwritten."""
    path = path.expanduser().absolute()
    if ".." in path.parts or path.suffix.lower() != ".md":
        raise ValueError("Choose a .md output path without '..'")
    # Downloads may intentionally be redirected. Resolve that chosen directory,
    # then use no-follow directory handles for the actual POSIX mutation.
    parent = path.parent.resolve()
    if os.name == "posix":
        from agent_links import _directory
        with _directory(parent, create=True) as (fd, _):
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                file.write(content)
    else:
        parent.mkdir(parents=True, exist_ok=True)
        with (parent / path.name).open("x", encoding="utf-8") as file:
            file.write(content)
    return parent / path.name


def dashboard_name() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"agent-skill-gate-backup-scan-{stamp}-{uuid.uuid4().hex[:8]}.md"


def export_dashboard(records: list[dict], stage: Path, *, output: Path | None = None, warnings: list[str] | None = None) -> tuple[Path, Path | None]:
    content = render_dashboard(records, warnings=warnings)
    name = dashboard_name()
    local = write_markdown(stage / "reports" / name, content)
    try:
        downloaded = write_markdown(output if output is not None else downloads_directory() / name, content)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Could not export to Downloads: {visible(exc)}")
        print(f"Dashboard saved locally: {visible(local)}")
        return local, None
    print(f"Markdown dashboard: {visible(downloaded)}")
    return local, downloaded


def load_review_reports(stage: Path, *, run_id: str | None = None) -> tuple[list[dict], list[str]]:
    records, warnings = [], []
    folder = stage / "reports"
    # Loading JSON is read-only and never executes skill or report contents.
    for path in sorted(folder.glob("review-*.json")):
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise ValueError("not a bounded regular JSON report")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "r", encoding="utf-8") as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise ValueError("report changed while opening")
                record = json.load(file)
            if not isinstance(record, dict) or record.get("job") != path.stem:
                raise ValueError("not a matching review record")
            if (
                not isinstance(record.get("skill"), str)
                or record.get("agent") not in ("codex", "claude", "cursor")
                or not isinstance(record.get("source"), str)
                or not isinstance(record.get("action"), str)
                or record["action"] not in {"promote", "quarantine", "decline", "skip", "defer", "pending"}
            ):
                raise ValueError("invalid backup review metadata")
            if run_id is not None and record.get("run_id") != run_id:
                continue
            record["report_file"] = str(path)
            records.append(record)
        except (OSError, ValueError, UnicodeError) as exc:
            warnings.append(f"Skipped {path.name}: {exc}")
    records.sort(key=lambda record: (str(record.get("time", "")), str(record.get("source", ""))))
    return records, warnings
