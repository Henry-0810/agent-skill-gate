# Architecture

This document describes the current implementation. Proposed integrations are separated at the end. For dated verification and outstanding work, read [HANDOFF.md](HANDOFF.md); for limitations, read [SECURITY.md](SECURITY.md). Contributor instructions live in [AGENTS.md](../AGENTS.md).

## Purpose and implemented scope

Agent Skill Gate is a cooperative local pre-install scanner and installer for a shared agent-skills vault. It prepares bounded snapshots, runs NVIDIA SkillSpector in Docker, applies policy, promotes eligible content, and retains reports/quarantine. The Python application uses the standard library. The scanner and optional filesystem automation are external programs.

The current CLI accepts an already-materialized local skill directory under staging `build/`. It does not fetch a repository URL for installation, expose an MCP server, intercept arbitrary installers, or enforce agent filesystem permissions. Full CLI support is macOS/POSIX, not native Windows.

## Components

| File | Responsibility / principal entry points |
| --- | --- |
| `agent_skill_gate.py` | `main()` CLI; `initialize`, `submit`, `process`, `scan_payload`, `promote_payload`; Docker/Watchman adapters; `new_review`, `prepare_review`, `apply_review`, `finalize_review`; wizard and readiness checks |
| `agent_links.py` | Agent selection; `_directory` opens ancestor directories without following symlinks; `_locations`/`_plans` validate layout; `setup_links`/`verify_links`; exclusive backup slots and rollback |
| `agent_review.py` | Shared `scan_problem` policy; report parsing/escaped terminal output; numbered/group selection; `ReviewJob`; bounded recursive discovery of backup skill roots |
| `agent_dashboard.py` | Markdown rendering, historical JSON loading, exclusive output creation, OS-specific Downloads discovery; exports cannot install skills |
| `agent_demo.py` | Disposable fake home, sample skill directories and optional retained profile; simulated scanner by default, optional real scanner; Watchman and notifications disabled |
| `scripts/build-scanner.sh` | Build upstream scanner image from an explicit 40-character commit SHA; record the commit; refuse an existing source checkout |
| `tests/` | `unittest` suites for gate, links, review, dashboard and demo |

Module dependencies are `agent_skill_gate` → links/review/dashboard and, only for demo dispatch, `agent_demo`. Review reuses link validation; dashboard reuses review parsing. Demo receives the active gate module so it can temporarily substitute its home/scanner adapters without recursively importing the CLI.

## Storage and configuration

Defaults are relative to the user's home:

```text
~/.agent-staging/
  build/        proposed raw source (download/extraction safety is external today)
  incoming/     <name>--<jobid>/{name,payload/,READY}
  processing/   automatic scan jobs and crash-recovery backlog
  reviews/      inert interactive snapshots; no READY marker
  quarantine/   blocked or declined snapshots
  reports/      per-job JSON, review preview Markdown and final dashboards
  logs/events.jsonl
  .watchmanconfig
  .processing.lock
~/.local/share/agent-skills/                       approved vault
~/.local/state/agent-skill-gate/backups/<slot>/skills/  preserved originals
~/Downloads/                                     default dashboard export
```

`AGENT_GATE_STAGING` / `AGENT_GATE_VAULT` configure roots; global `--staging` / `--vault` options override them and precede the subcommand. `AGENT_GATE_DOCKER_BIN` and `AGENT_GATE_SCANNER_IMAGE` select Docker and its scanner image. Default image: `agent-skill-gate-scanner:local`.

Codex `~/.agents/skills` and Claude `~/.claude/skills` are the default managed symlinks; Cursor `~/.cursor/skills` is opt-in via `--agents`. Agent selection is not persisted. Link-management and guided-review validation require physical directories without symlink ancestors; overlap checks include filesystem identity for case-insensitive aliases. Legacy `initialize` checks managed directory entries but does not apply the same full ancestor traversal to every creation path.

## Automatic submission flow

1. `submit` validates the source's resolved containment under `build/`, directory name and regular `SKILL.md`.
2. It copies to `incoming/.tmp-<job>/payload/`, writes name metadata, renames the job, then publishes `READY` last via rename. Partial submission cleanup affects only that job.
3. Either Watchman invokes `process`, or the user invokes it manually. Watchman is a convenience trigger, not an interception mechanism.
4. `process` holds an exclusive `fcntl` lock, rescans abandoned `processing/` jobs, then moves eligible `READY` jobs from `incoming/` to `processing/`.
5. `scan_payload` hashes the snapshot, runs Docker, records output, and verifies its hash again. `scan_problem` decides eligibility. `promote_payload` rechecks the hash and destination absence, then renames the payload into the vault.
6. Success removes the job wrapper. Failure moves the job to quarantine. JSON evidence, JSONL events and best-effort macOS notifications record the outcome.

Snapshots reject symlinks, special files and `.git`/`.hg`/`.svn`/`READY` entries; enforce 3,000 files, 50 MiB total, 10 MiB per file and directory-depth bounds; normalize permissions. Fingerprints include relative paths, modes, entry types and file contents. Promotion rename requires the same filesystem. These are best-effort race checks, not immutable sealed handoffs.

## Scanner and policy

Each scan uses a disposable container: `--rm`, `--pull never`, no networking, read-only root/source mount, dropped capabilities, no new privileges, non-root UID/GID, CPU/memory/process limits and bounded writable `/tmp`. No host credentials or Docker socket are mounted. The scanner command is `scan /scan --no-llm --format json --fail-on-incomplete`; timeout is 300 seconds. The Docker runtime is an independent dependency and can remain running.

| Condition | Automatic `process` | Interactive review |
| --- | --- | --- |
| Valid SAFE, exit 0 | Promote after snapshot checks | Only explicitly selected rows; SAFE group selection permitted |
| Valid complete CAUTION, exit 0 | Quarantine | Separate per-skill risk acceptance; `--safe-only` blocks it |
| High/critical overall risk, score >50, disallowed recommendation, nonzero exit, malformed report or explicit incomplete metadata | Block | Block; no approval bypass |

Missing completeness metadata from older scanners is shown as unreported and relies on the strict exit-code contract. Overall recommendation and individual finding severity are distinct; a SAFE score band may include a HIGH finding. Static scoring is a heuristic, not a compromise probability or guarantee of execution safety.

## Interactive migration and reports

`init` only prepares storage. `setup-links` is explicit: preflight all selected paths, preserve each real skill directory in a unique private backup slot, and create its link. Correct links are skipped. Unexpected/broken links and other objects are refused. Failed link creation attempts safe restoration; cross-agent migration is not transactional.

`setup` checks/creates missing storage, checks Docker/image and a harmless real scanner fixture, previews/applies necessary links, verifies them, then reviews backups. It offers Watchman registration only when not already configured. Registration also processes existing READY backlog. `doctor` inspects layout, links, image/runtime and matching Watchman configuration; `--scan` additionally scans temporary input without installing it. Registration is not event-delivery verification.

`review-backups` discovers nested backup skill roots without following links, scans before decisions, and displays one numbered table. `s` selects listed eligible SAFE rows; row numbers select specific candidates; `v N` shows details; Enter/`n` declines remaining rows. CAUTION always asks separately. Interactive commands require a terminal; there is no headless `--yes` mode.

Review jobs never enter `incoming/` or `processing/`. Full `scan.json` evidence and preview Markdown exist before selection. Consent is logged before promotion and snapshots are rehashed after selection. Final per-job JSON records retain source, original verdict, hash, consent and outcome. Interrupted unapproved jobs remain inert. Duplicate installed names are skipped without rescanning or replacement.

Dashboards are exported locally and to Downloads (macOS home folder, Linux XDG configuration, Windows Known Folder lookup). Outputs are new files; export failure retains the local fallback and causes a nonzero exit. `export-report` reads saved `review-*.json` without rescanning; by default it includes all review history, optionally filtered by a new-format `run_id`. Historical skipped records are not clean scan verdicts.

`setup --demo` substitutes a fresh temporary home and fixed labelled scanner fixtures while using the real wizard. Downloads stays inside the profile even with redirected XDG configuration; actual HOME remains unchanged for Docker connectivity. Normal exit/Ctrl-C cleans the profile unless `--keep-demo`; `--real-scan` uses real Docker on harmless samples only. Both demo modes disable Watchman/notifications. This is test isolation, not a production permission boundary.

## Proposed direction — not implemented

The user's desired product is: install one package, connect supported agents once, then request skill installation in chat or a CLI without managing staging paths.

Proposed flow: agent/CLI request → trusted source fetch and snapshot → isolated scanner → policy/human approval → promotion → structured result back to the requester. A common installation API could be wrapped by a local stdio MCP adapter for Claude Code, Codex and tool-capable local agents. Tool names such as `request_skill_install` / `get_install_status` are proposals, not current endpoints. Watchman could remain an optional legacy queue adapter.

MCP publishes capabilities; natural-language tool selection remains model behavior. Instructions and host hooks can steer/block covered operations, but an enforced claim requires protected managed paths, gate code/configuration and approval authority. A separate identity or suitably restricted agent sandbox is still a design decision. A model-supplied `approved=true` must not constitute human consent. A service running as the same unrestricted user does not establish that boundary.

No MCP server, URL installer, Homebrew formula, signed release workflow, host hook integration, permission-boundary setup, privileged broker or native Windows gate implementation exists here. ChatGPT integration has separate surface/account/local-execution constraints; current vendor documentation must be checked when designing it. No universal interception claim is justified.
