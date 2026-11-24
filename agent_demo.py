"""Repeatable wizard demo confined to a newly created temporary profile."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import agent_dashboard
from agent_links import AGENT_DIRECTORIES
from agent_review import scan_problem


SAMPLES = ("demo-safe", "demo-caution", "demo-incomplete", "demo-blocked")


def simulated_scan(payload: Path) -> tuple[int, dict, str]:
    """Predetermined UI fixtures, never evidence of a real security scan."""
    manifest = (payload / "SKILL.md").read_text(encoding="utf-8")
    name = next((name for name in SAMPLES if f"name: {name}\n" in manifest), "demo-safe")
    recommendation, score, severity, complete, code = {
        "demo-safe": ("SAFE", 0, "LOW", True, 0),
        "demo-caution": ("CAUTION", 35, "MEDIUM", True, 0),
        "demo-incomplete": ("CAUTION", 37, "MEDIUM", False, 1),
        "demo-blocked": ("DO_NOT_INSTALL", 80, "HIGH", True, 1),
    }[name]
    issues = [] if name == "demo-safe" else [{
        "id": "DEMO", "severity": severity,
        "finding": "Simulated finding for testing the wizard; this is harmless sample text.",
        "explanation": "This rating is a fixed UI fixture, not a scanner assessment.",
        "location": {"file": "SKILL.md", "start_line": 1},
        "remediation": "No sample repair is needed. Use --real-scan to exercise SkillSpector.",
    }]
    return code, {
        "risk_assessment": {"recommendation": recommendation, "score": score, "severity": severity},
        "analysis_completeness": {"is_complete": complete, "coverage_percent": 100 if complete else 66.7, "execution_successful": True},
        "metadata": {"demo": True, "skillspector_version": "simulated-demo", "llm_requested": False},
        "issues": issues,
    }, ""


def run_demo(gate, agents: tuple[str, ...], *, real_scan: bool = False, keep: bool = False, allow_caution: bool = True) -> int:
    # Check before creating anything, so piped/headless runs cannot mutate even
    # scratch state or become an implicit approval mechanism.
    gate.require_terminal()
    temporary = (
        contextlib.nullcontext(tempfile.mkdtemp(prefix="agent-skill-gate-demo-"))
        if keep else tempfile.TemporaryDirectory(prefix="agent-skill-gate-demo-")
    )
    root = None
    try:
        with temporary as folder:
            root = Path(folder).resolve()
            home = root / "home"
            home.mkdir()
            stage = home / ".agent-staging"
            vault = home / ".local" / "share" / "agent-skills"
            for agent in agents:
                (home / AGENT_DIRECTORIES[agent] / "skills").mkdir(parents=True)
            for index, name in enumerate(SAMPLES):
                agent = agents[index % len(agents)]
                skill = home / AGENT_DIRECTORIES[agent] / "skills" / name
                skill.mkdir()
                (skill / "SKILL.md").write_text(
                    f"---\nname: {name}\ndescription: Harmless documentation-only wizard test.\n"
                    "---\n# Sample skill\nSummarize selected public documentation.\n",
                    encoding="utf-8",
                )
            print("\nDEMO PROFILE — " + ("REAL SCANNER, harmless samples only" if real_scan else "SIMULATED SCANNER RESULTS"))
            print(f"Temporary profile: {root}")
            print("Real skills, staging, backups, Downloads and Watchman will not be changed.")
            print("Reports stay inside this profile. " + ("Files will be kept." if keep else "Files are removed on exit, including Ctrl-C."))
            with contextlib.ExitStack() as scoped:
                # Do not change HOME: real Docker mode still needs the user's
                # Docker context. All gate-managed paths derive from this
                # patched Path.home or explicit scratch stage/vault arguments.
                scoped.enter_context(patch.object(Path, "home", return_value=home))
                # Linux XDG settings may redirect Downloads outside HOME.
                scoped.enter_context(patch.object(agent_dashboard, "downloads_directory", return_value=home / "Downloads"))
                scoped.enter_context(patch.object(gate, "notify", return_value=None))
                scoped.enter_context(patch.object(gate, "register", side_effect=RuntimeError("Watchman is disabled in demo mode")))
                scoped.enter_context(patch.object(gate, "watchman_registered", side_effect=RuntimeError("Watchman is disabled in demo mode")))
                if not real_scan:
                    scoped.enter_context(patch.object(gate, "docker_scan", side_effect=simulated_scan))
                    scoped.enter_context(patch.object(gate, "scanner_ready", side_effect=lambda: print("DEMO scanner: fixed simulated results; no Docker required.") or True))
                    scoped.enter_context(patch.object(gate, "scanner_self_test", side_effect=lambda: print("DEMO scanner self-test: simulated, not a real integration test.") or True))
                code = gate.guided_setup(stage, vault, agents, allow_caution=allow_caution, demo_mode=True)
            if not real_scan and code == 1:
                # Blocking the two intentional fixtures is a successful demo,
                # provided the run actually completed and exported its report.
                reports = [json.loads(path.read_text()) for path in (stage / "reports").glob("review-*.json")]
                blocked = [row for row in reports if row.get("action") == "quarantine"]
                expected_blocks = all(
                    row["skill"] in {"demo-blocked", "demo-incomplete", "demo-caution"}
                    and row.get("reason") == scan_problem(row["scanner_exit"], row["scanner"], allow_caution=allow_caution)
                    for row in blocked
                )
                if len(reports) == len(SAMPLES) and blocked and expected_blocks and list((home / "Downloads").glob("*.md")):
                    print("Demo completed: intentional blocked examples behaved as expected.")
                    code = 0
            return code
    finally:
        if root is not None:
            if keep:
                print(f"Demo files kept at: {root}")
            elif root.exists():
                print(f"Demo cleanup incomplete; files remain at: {root}")
            else:
                print(f"Demo files removed: {root}")
