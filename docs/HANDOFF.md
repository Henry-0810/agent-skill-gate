# Session handoff

Updated **2026-11-13 (Asia/Kuala_Lumpur)** after repository inspection and fresh validation. Start with [AGENTS.md](../AGENTS.md) for stable working instructions and [ARCHITECTURE.md](ARCHITECTURE.md) for the implemented data flows. This file records status and next work; it is not authorization to reconfigure the user's machine.

## 1. Objective and current direction

Build an open-source local security gate for agent skills shared by Claude Code, Codex and potentially Cursor. Current implementation scans bounded snapshots with NVIDIA SkillSpector in Docker before promotion into a shared vault.

The user's clarified product goal is **one package install plus one-time agent connection**, then natural-language/CLI install requests automatically handed to the gate. Users should not manage staging paths, manually adjust permissions, or repeatedly approve routine SAFE rows. A skill/instruction file alone cannot deterministically route every install request. MCP is a proposed callable front door; preventing bypass requires a separately designed permission boundary.

Recent conversation was design discussion only. MCP, automatic source fetching, distribution, agent hooks and enforced permissions have **not** been implemented or selected as the next authorized implementation task. Proposed integrated mode relies on cooperative agents; proposed enforced mode would configure and test actual restrictions. Do not present either label as an implemented setup option.

## 2. Implemented features and code map

| Area | Files / useful functions | Implemented behavior |
| --- | --- | --- |
| Core gate | `agent_skill_gate.py`: `submit`, `process`, `scan_payload`, `promote_payload`, `docker_scan` | Local source submission, atomic READY publication, serialized processing/recovery, constrained scans, hashes, policy, no-overwrite promotion, quarantine and JSON/JSONL |
| Links | `agent_links.py`: `setup_links`, `verify_links`, `_directory`, `_locations`, `_plans` | Default Codex/Claude links; opt-in Cursor; preview, conflict detection, separate backups, rollback, case-alias/ancestor checks |
| Human review | `agent_skill_gate.py`: review lifecycle functions, `review_backups`, `guided_setup`; `agent_review.py` | Scan-first numbered table; one explicit SAFE group selection; separate CAUTION consent; incomplete/error/high-risk blocking; inert review queue |
| Reports | `agent_dashboard.py`; CLI `export-report` | Readable findings/explanations/fixes, escaped Markdown, private new output files, Downloads detection, legacy JSON export and optional run filtering |
| Repeatable demo | `agent_demo.py`; `setup --demo` | Fresh fake home/sample skills; simulated results by default, optional real scanner; cleanup or retention; no real Watchman/Downloads changes |
| External adapters | `scripts/build-scanner.sh`, Watchman functions in core | Explicit pinned-source scanner build and optional READY trigger registration; no bundled scanner |
| Tests | `tests/test_gate.py`, `test_links.py`, `test_review.py`, `test_dashboard.py`, `test_demo.py` | Regression, filesystem safety, CLI dispatch, review policy, demo isolation and report export |
| User documentation | `README.md`, `docs/SECURITY.md`, `docs/AGENT_POLICY.md` | Operations/recovery, threat model, advisory agent installation contract |

Current subcommands: `init`, `setup-links`, `verify-links`, `setup`, `review-backups`, `export-report`, `doctor`, `submit`, `process`, `register`, `status`, `unregister`. There is **no** `install`, MCP, bootstrap, or enforce-mode command.

## 3. Decisions and rationale

- Keep automatic processing **SAFE-only**. The user explicitly chose per-skill CAUTION acceptance in human review; its original recommendation remains recorded. Incomplete/error/high-risk results cannot be approved. One explicit SAFE group selection replaced repetitive Yes prompts; CAUTION never joins it implicitly.
- Preserve originals in backups outside the vault. `init` never migrates agent directories; setup skips already-configured steps. Existing names are not upgraded/merged. Reports of skipped names must say not rescanned.
- Separate `reviews/` from automatic `incoming/` and `processing/`: background workers must not install snapshots while the user is considering approval. Log consent and rehash before promotion.
- Keep scanner isolation and triggering separate. Watchman is optional automation; Docker is the only current real scanner backend. A normal host subprocess or virtualenv is not an equivalent sandbox.
- Keep simulated demo results explicit and disposable. A successful wizard simulation does not verify Docker, scanner findings or filesystem event delivery.
- Future integrations should reuse one source/scan/policy/promotion implementation. Tool discovery/instructions provide convenience; OS restrictions would provide enforcement. No privileged service or permission changes have been approved as an implementation design.

## 4. Verification ledger

**Freshly verified in this handoff session:**

- `python3 -B -m unittest discover -s tests -v`: **117 tests passed**, exit 0, on local macOS Python **3.15.2**. The suite mocks external services and confines skill mutations to temporary profiles. Its real-scanner demo test uses a mocked scanner; it is not live Docker proof.
- Root CLI help and `setup --help` execute and list the current commands/demo flags.
- Read-only filesystem inspection: Codex and Claude paths point to `~/.local/share/agent-skills`; vault has **8 immediate entries**, backups have **2 slots**, and staging has **39 saved review JSON records**. Counts are observations, not an integrity audit or approval attestation.
- The previously generated Downloads dashboard exists. Its content was not regenerated in this documentation task.

**Historical evidence from the preceding conversation (not rerun here):**

- User supplied real wizard logs: Docker runtime/image checks and scanner self-test succeeded; initial backup review recorded **13 entries: 8 promotions, 2 quarantines, 3 skips**. Both `obsidian-bases` records had incomplete analysis (66.7% / 50% coverage), so CAUTION acceptance was unavailable. Overall SAFE entries could still contain individual HIGH findings.
- Logs ended with successful Watchman registration/backlog processing, **not** proof of a later READY event being delivered. No end-to-end Watchman event test was established.
- The assistant exported the initial 13-record dashboard to `~/Downloads/agent-skill-gate-backup-scan-20261109T005119Z-601788f2.md` and verified its sections/counts and POSIX mode `0600` at that time.
- A simulated demo was exercised through a real terminal, exited 0 and removed its temporary root. Fresh automated tests also cover repeatability and cancellation cleanup.

**Not verified:** current Docker/image availability or source provenance; real `--demo --real-scan`; Watchman event delivery; every CI matrix interpreter; native Windows; agent discovery after installation; any MCP integration or enforced isolation. Prior reports that the image was missing were superseded by the user's successful scanner logs, but do not infer current service health from those logs.

## 5. Work in progress, bugs and risks

The workspace is **now a Git repository**, HEAD `bc7fc36` (`init`). Older chat/memory saying no Git checkout is stale. At task start, tracked modifications were `README.md`, `agent_skill_gate.py`, `agent_review.py`, `agent_dashboard.py`; untracked files were `AGENTS.md`, `agent_demo.py`, `tests/test_demo.py`, `docs/HANDOFF.md`, `docs/ARCHITECTURE.md`. The three instruction/handoff/architecture files were empty placeholders. This task fills only those three documents and leaves application/test changes intact.

Concrete current behaviors needing follow-up:

1. `doctor` returns failure if no matching Watchman trigger exists, although manual processing works and automation is optional. Proposed improvement: distinguish core readiness from optional automation status.
2. `submit` always prints that Watchman will pick up READY, even when unregistered. Message should describe the queued job and manual recovery accurately.
3. Normal `setup` still requires Docker/scanner readiness; no native backend, dependency bootstrap or distribution package exists. The build script refuses an existing scanner checkout, so rerunning it is not an update workflow.
4. Current core uses POSIX `fcntl`, no-follow directory descriptors and rename semantics. Mocked Windows Downloads lookup is not native Windows gate support. Managed symlink ancestors (including macOS `/tmp` aliases) are deliberately refused; use physical paths in tests.
5. Validation is not uniform across commands: link/guided-review helpers walk ancestors with no-follow directory opens, while legacy `initialize` checks managed entries and uses path-based parent creation. Review that difference before claiming every entry point has identical path-race protections.

Security review items **identified by inspection, not reproduced exploits**: scanner stdout is fully captured before its 8 MiB check; killing a timed-out Docker CLI may leave its container running because there is no explicit container-ID cleanup. Add targeted tests/design before changing them.

See [SECURITY.md](SECURITY.md) for the full risk model: same-user bypass and remaining TOCTOU windows, mutable scanner tags, static-only/limited coverage, bypass through other agent/project/plugin paths, non-transactional promotion/reporting, unauthenticated human intent at the OS level, and unsupervised disk retention. Setup currently establishes no agent sandbox, vault-owner separation, ACL enforcement, protected approval broker or integrity inventory.

## 6. Setup, testing and validation commands

Run from the repository root with Python 3.10+. These commands do not require a package/dependency install:

```bash
python3 -B -m unittest discover -s tests -v
python3 -B agent_skill_gate.py --help
python3 -B agent_skill_gate.py setup --help
```

Repeatable interactive testing (a terminal is required):

```bash
python3 agent_skill_gate.py setup --demo
python3 agent_skill_gate.py setup --demo --keep-demo
python3 agent_skill_gate.py setup --demo --real-scan
```

Default demo needs neither Docker nor Watchman. It seeds harmless SAFE/CAUTION/incomplete/blocked fixtures, confines exports to its fake Downloads, ignores real staging/vault settings and removes only its own root on normal exit/Ctrl-C. `--keep-demo` prints the retained path; forced termination may leave scratch files. `--real-scan` needs a running runtime and trusted local image and may return different real verdicts. Both modes disable Watchman; they do not test event delivery. Do not combine demo with custom staging/vault/report-output paths.

Real installation operations below are operational instructions, **not commands run in this documentation task**:

```bash
# Build only after choosing/reviewing an official NVIDIA 40-character commit.
./scripts/build-scanner.sh <REVIEWED_40_CHARACTER_COMMIT_SHA>
python3 agent_skill_gate.py init
python3 agent_skill_gate.py setup-links --dry-run
python3 agent_skill_gate.py setup-links
python3 agent_skill_gate.py verify-links
python3 agent_skill_gate.py doctor --scan
python3 agent_skill_gate.py review-backups
python3 agent_skill_gate.py register
python3 agent_skill_gate.py status
python3 agent_skill_gate.py export-report
```

`setup` combines the guided flow; `--safe-only` tightens manual policy. Global `--staging`/`--vault` precede the subcommand, but **those two options alone do not isolate real agent link paths**. Use demo mode for first-run testing. `export-report --output ./new-report.md` avoids default Downloads; existing files are refused. Default export now reads all saved history (39 records at inspection), not only the original 13. `--run-id` filters sessions recorded by the new batch flow; older reports lack that grouping.

To test future automatic processing, follow the README's harmless demo submission, ensure Watchman rather than a manual `process` call handles it, and inspect the outcome/report. `submit` followed by `process` validates the manual path only. `doctor --scan` may exit 1 solely because automation is unconfigured even if its scanner self-test passes. Review exits 1 for blocked/export-failed results and 130 for Ctrl-C. CI is configured for Ubuntu Python 3.10/3.12/3.13/3.15; its remote results were not inspected.

## 7. Exact next steps, in priority order

1. **Resolve the next product slice with the user.** Confirm integration-first scope for CLI + Claude Code/Codex and one tool-capable local-agent host, versus an enforced permission-boundary prototype. The desired UX is known; implementation authorization, platform support and the enforcement model remain open. Avoid another round of wizard expansion as a substitute for the missing install entry point.
2. **Specify the shared install request contract.** Decide accepted sources/ref pinning, target naming, bounded safe fetching/extraction, durable job/status schema, cancellation and concurrency. Specify human approval bound to source/hash/job/policy, with no agent-controlled approval boolean. Keep existing no-overwrite/update restrictions explicit.
3. **Implement and test the source-to-install core/CLI first when requested.** Reuse existing snapshots, policy and promotion. Own source acquisition inside the gate rather than asking an LLM to run arbitrary fetch/install scripts. Cover source traversal, malicious links, changes after scan, failed scanner, failed approval and duplicate names.
4. **Wrap the same core in a local stdio MCP adapter.** Proposed request/status tool names are not implemented APIs. Define progress/polling and trusted human consent outside the requesting model. Add protocol and agent integration tests; verify live vendor support/limitations before claiming universal ChatGPT/local-agent compatibility.
5. **Prototype enforcement separately if selected.** Protect managed vault paths, gate/config/approval authority and relevant alternate discovery paths; verify a real agent write is denied while approved promotion works. Evaluate sandbox vs distinct installer identity. Hooks may supplement this but cannot make natural-language routing deterministic; explicitly test fail-closed errors and unavailable adapters.
6. **Package and validate before release.** Decide Homebrew/release artifacts and dependency provisioning with clear user consent; pin scanner provenance and plan updates/rollback. Fix readiness/messaging discrepancies above, test timeout/resource cleanup and real Watchman delivery, then run supported-platform tests. No formula, signed installer or daemon deployment is present today.

Open questions for that design: exact local-agent host; supported ChatGPT surface/connection; user-level process versus protected broker; handling project-local skills; trusted approval UI; scanner distribution/trust/update model; and whether existing skill version updates belong in the first release. Do not silently treat these as decided.
