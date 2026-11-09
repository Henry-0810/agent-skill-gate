# Agent Skill Gate — Watchman + SkillSpector (macOS)

Fail-closed *pre-installation scanning* for a shared local AI-agent skills library. Designed for Claude Code, Codex, and Cursor. **This is a security control for cooperative tooling, not an OS-enforced firewall against an agent running as your macOS user.** See [Security limitations](docs/SECURITY.md).

## Pipeline

```text
Untrusted source (git clone, downloaded archive extracted safely, agent-written skill)
  -> ~/.agent-staging/build/<skill>/SKILL.md
  -> python3 agent_skill_gate.py submit <path>
  -> ~/.agent-staging/incoming/<skill>--<jobid>/READY (atomic submission)
  -> Watchman trigger (invokes process)
  -> isolated snapshot in ~/.agent-staging/processing/
  -> NVIDIA SkillSpector in constrained Docker container (read-only mount, no network)
      SAFE + exit 0 + complete + same hash -> atomic install in master vault
      CAUTION / DO_NOT_INSTALL / error -> ~/.agent-staging/quarantine/
  -> JSON reports in ~/.agent-staging/reports/, events in logs/events.jsonl
```

Default: **no existing skills are overwritten**, symlinks and special files in skill packages are rejected, all scanner failures block, no untrusted skill code is run by the gate.

## Prerequisites

- macOS, Python **3.10+**, `git`, and the already-installed **Watchman** (`brew install watchman`).
- Local container runtime running with a Docker-compatible CLI. **Free option:** `brew install colima docker`, then `colima start --cpu 2 --memory 4` and `docker info`. Docker Desktop is another option.
- NVIDIA's official **SkillSpector** Dockerfile. This project does **not** bundle, modify, or redistribute SkillSpector.

## Guided setup and review of existing skills

For personal use, this is a cooperative pre-install review gate: it preserves originals, scans snapshots, applies an installation policy, and records decisions. It is not a filesystem firewall, a guarantee that approved code is safe to execute, or a replacement for reviewing what an agent can access. A working link alone does not prove that scanning or Watchman delivery works.

Build the pinned scanner image using the instructions in **Scanner and watcher setup** below, then start the guided flow:

```bash
python3 agent_skill_gate.py setup
```

The wizard has four labelled steps: installation checks, agent folders, backup review, and future submissions. It skips initialization, link changes and Watchman registration when they are already configured. It asks before creating missing storage or migrating directories. Before link migration it checks the local Docker runtime/image and runs the constrained scanner against a harmless temporary skill, showing one success line instead of the fixture's full report. It never installs prerequisites or downloads scanner images automatically. If those checks fail, existing agent skill directories are not moved.

Already ran `init`, `setup-links` and `verify-links`? Your backups have not been scanned automatically. You can resume just the review step:

```bash
python3 agent_skill_gate.py doctor
python3 agent_skill_gate.py review-backups
```

`doctor` inspects storage, selected links, the local Docker runtime/image, and the matching Watchman trigger. It does not migrate skills or change registrations; service clients may access their own runtime state. `doctor --scan` additionally creates and scans a harmless temporary fixture, then removes it without installing it. A missing trigger still produces exit code 1 even when the scanner self-test passes. A passing trigger check confirms configuration, not delivery of a filesystem event.

Backup review discovers skill folders inside backups for the selected agents, including nested category folders such as `.system`. Discovery never follows backup symlinks. Each candidate is copied into a private review job, scanned with the same Docker restrictions as future submissions, and fingerprinted before and after scanning. The original backup stays untouched. Unsupported names, contained symlinks, excessive size, or a changed snapshot block installation. An existing name in the vault is skipped without replacement or rescanning; `doctor` and this wizard are not an integrity audit of already-installed vault contents.

Review scans the backup candidates **before making installation decisions**. Progress uses one line per candidate, followed by a comparison table with risk score, coverage, finding count, highest finding severity and decision status. The scanner's overall recommendation and individual finding severity are separate: an overall `SAFE` result can still have a `HIGH` finding. Incomplete coverage is labelled `INCOMPLETE`, and its reason is shown before a generic process-exit error. For example (illustrative, not a scan of your skills):

```text
BACKUP SCAN RESULTS
  #  Skill                    Agent  Verdict       Risk  Cover Issues Highest  Decision
  1  documentation-helper     codex  SAFE             0   100%      0 none     Choose
  2  frontend-design          claude SAFE            13   100%      1 HIGH     Choose
  3  server-helper            claude CAUTION         49   100%      4 HIGH     Choose
  4  partial-review           codex  CAUTION         37  66.7%      2 HIGH     INCOMPLETE

Choose what to install:
  s       Install the listed SAFE recommendations together
  1,3,5   Install selected row numbers (CAUTION asks separately)
  v 3     View a row's findings and explanation
  n       Finish without installing remaining rows [default]

Your choice [n]:
```

Entering `s` explicitly approves the listed, eligible `SAFE` rows together, removing the repeated per-skill Yes prompts. Choosing row numbers authorizes those eligible rows. A selected `CAUTION` row first displays its findings and still requires its own risk-acceptance prompt, default **No**. `v 3` shows the third row's details without selecting it. Enter or `n` finishes without installing remaining rows. Invalid selections and blocked/existing rows cannot grant approval. The table uses a compact two-line layout on narrower terminals. No terminal colors or third-party UI packages are required.

Finding details read the scanner's `finding` and `explanation` fields as well as compatible message fields, so the UI shows the actual concern instead of only an ID such as `AR2`. Full evidence is saved before decisions in `reviews/<job>/scan.json`. A private Markdown preview under `reports/` lists all rows and their findings before the choice menu. JSON remains the authoritative detailed record; Markdown exports never grant or replay approval.

NVIDIA documents a [0–100 risk score and machine-readable recommendation](https://github.com/NVIDIA/SkillSpector#machine-readable-output). Higher scores mean more estimated risk; **35/100 does not mean a 35% probability of compromise**. This gate uses `--no-llm` and disables container networking, so it provides static checks without semantic LLM inspection or live CVE lookups. A low score can miss malicious instructions or behavior. The image you build is pinned to its chosen source commit; its output may differ from the latest upstream documentation.

| Result | Interactive setup / backup review | Future Watchman submissions |
| --- | --- | --- |
| `SAFE`, exit 0, valid report | Install only explicitly selected rows; one menu action can select all listed SAFE rows | Install automatically if snapshot checks pass |
| `CAUTION`, exit 0, valid complete report | Ask explicitly whether to accept the reported risks, default **No** | Quarantine |
| `DO_NOT_INSTALL` or high/critical overall risk | Block; no approval prompt | Quarantine |
| Error, invalid report, incomplete scan or changed snapshot | Block; no approval prompt | Quarantine |

Use `setup --safe-only` or `review-backups --safe-only` to block `CAUTION` during manual review too. Both commands support `--agents codex,claude` (default) or an explicit selection including `cursor`. SAFE group approval records the exact selected jobs and skills, and each installation records its approval method. There is no headless approve-all/`--yes` option, CAUTION is never implicitly included in SAFE group approval, and piped input is rejected. Missing completeness metadata from older scanner versions is shown as unreported; the `--fail-on-incomplete` exit policy is still enforced. Explicit invalid/incomplete metadata always blocks.

Choosing **No** preserves the original and leaves the skill inactive through the shared vault; it does not delete the backup. Its inspected copy is retained in quarantine with a `decline` decision, which is not a claim that it is malicious. `CAUTION` acceptance records your consent, timestamp, source, snapshot hash and original recommendation without relabeling it `SAFE`. Consent is logged before promotion and the fingerprint is checked again after the prompt. Detailed outcomes are stored in `~/.agent-staging/reports/review-*.json`, with events in `logs/events.jsonl`. Review returns 1 if any candidate was blocked, 0 for a completed review with installations/declines/skips, or 130 on Ctrl-C. Source backups and review/quarantine snapshots need manual retention management; repeated reviews of declined skills create new snapshots/reports.

### Markdown scan dashboard in Downloads

Every review run exports a Markdown dashboard when it finishes or is cancelled after scanning has started. It includes counts, per-backup results, overall scores and recommendations, coverage, individual findings and explanations, suggested fixes, source paths, approval methods and recorded outcomes. Repeated names from different backups have separate rows. Skipped existing names are labelled **not rescanned**, rather than receiving an invented clean score. The report is a historical record, not a live attestation of the vault. Terminal controls, HTML and Markdown from scanner text are escaped.

The output is saved both under staging `reports/` and to the endpoint user's Downloads directory, using a unique filename. Downloads discovery uses `~/Downloads` on macOS, the configured XDG Downloads directory on Linux, and the Windows Downloads Known Folder API with a home-directory fallback. See the [XDG directory configuration](https://wiki.freedesktop.org/www/Software/xdg-user-dirs/) and [Windows Known Folders documentation](https://learn.microsoft.com/windows/win32/shell/knownfolderid). Downloads resolution and Markdown format are portable; the scanner/Watchman CLI still targets macOS/POSIX. Native Windows execution is not covered by the macOS test run.

Already completed the initial review? Export its saved records **without rescanning or changing skills**:

```bash
python3 agent_skill_gate.py export-report
```

By default this includes all saved backup review JSON records; repeated review runs remain visible as separate records. New reviews record a `run_id`, which can restrict the export. Older JSON records, including the initial wizard's reports, are supported without inventing a session boundary:

```bash
python3 agent_skill_gate.py export-report --run-id backup-review-<id>
python3 agent_skill_gate.py export-report --output ./backup-scan.md
python3 agent_skill_gate.py setup --report-output ./setup-scan.md
```

Custom outputs must be new `.md` files. Existing files and symlinks are never overwritten. If Downloads cannot be written, the CLI prints the local fallback path and returns nonzero; scan decisions and JSON evidence are preserved. Exported files have owner-only permissions on POSIX. Reports include local paths and security findings, so review them before sharing.

Review snapshots live in `~/.agent-staging/reviews/`, separate from `incoming/` and `processing/`. They never receive `READY`, so a running Watchman worker cannot install them before approval. A cancelled review remains inert there. Rerunning review discovers the preserved backups again and makes a new scan; it does not trust an old approval or resume a partially read report. A crash between promotion and final reporting can still need manual reconciliation; the log is not a durable transaction or tamper-evident attestation.

For a machine with initialized storage and verified links, the remaining sequence is:

```bash
# Choose and review an official NVIDIA commit first; see the build instructions.
./scripts/build-scanner.sh <REVIEWED_40_CHARACTER_COMMIT_SHA>
python3 agent_skill_gate.py doctor --scan
python3 agent_skill_gate.py review-backups
python3 agent_skill_gate.py register
python3 agent_skill_gate.py doctor --scan
```

Watchman is for **future CLI submissions**: prepare a skill under `build/`, then call `submit`. It watches the resulting `READY` marker, scans and installs only `SAFE` results. It cannot intercept direct writes into the vault or active skills links. Its background process never asks questions or accepts `CAUTION`; those results stay quarantined for manual investigation. Finish the demo submission below to test actual event delivery before calling the whole pipeline verified.

## Quick start: unified skill storage

One approved vault lets supported agents discover the same scanned skills without keeping separate copies. A symbolic link is a filesystem entry pointing to another directory: opening `~/.agents/skills/demo-safe` accesses the corresponding folder in the vault. Writes through the link also reach the vault. **Links alone cannot prevent an agent with filesystem write access from bypassing the scanner.** Enforce permissions with separate OS identities/sandboxes when that boundary is needed.

Run from a trusted copy of this repository, outside active skill directories. Python 3.10+ is sufficient for link setup and verification; these commands do not invoke Docker, Watchman, installers, or skill code. Quit agent applications and pause skill installers while migrating directories.

```bash
python3 agent_skill_gate.py init
python3 agent_skill_gate.py setup-links --dry-run
python3 agent_skill_gate.py setup-links
python3 agent_skill_gate.py verify-links
```

Use `python` instead of `python3` if that is your Python 3.10+ executable. `init` only creates storage; it never migrates an agent directory. Link setup is a separate, explicit operation. Scanner setup and a real scan are still required before skills can be promoted (see below).

By default both link commands select Codex and Claude Code:

| Agent selection | Skills link | Destination |
| --- | --- | --- |
| `codex` (default) | `~/.agents/skills` | Approved vault |
| `claude` (default) | `~/.claude/skills` | Approved vault |
| `cursor` (opt-in) | `~/.cursor/skills` | Approved vault |

Cursor's [official skill-directory documentation](https://cursor.com/docs/skills) lists `~/.cursor/skills/` as a user-level location. Cursor also discovers `~/.agents/skills/`; a dedicated Cursor link may be unnecessary. This command checks filesystem links, not whether a particular installed agent version discovers them.

Select agents explicitly with a comma-separated list. Use the same selection when verifying; selections are not persisted:

```bash
python3 agent_skill_gate.py setup-links --agents codex,claude --dry-run
python3 agent_skill_gate.py setup-links --agents codex,claude
python3 agent_skill_gate.py verify-links --agents codex,claude

# Optional Cursor integration:
python3 agent_skill_gate.py setup-links --agents cursor --dry-run
python3 agent_skill_gate.py setup-links --agents cursor
python3 agent_skill_gate.py verify-links --agents codex,claude,cursor
```

`setup-links` checks **all selected paths before making changes**:

- Missing skills path: create missing agent parent directories and an absolute symlink to the vault.
- Correct existing link, including a relative link resolving to the vault: print `SKIP` and preserve it.
- Existing real directory: move it intact into a unique backup, then create the link. Contents, hidden files, permissions and contained symlinks are preserved by renaming the directory. No contents are merged into the vault.
- Incorrect, broken or looping symlink, regular file or special object: print `FAIL`, return nonzero and leave every selected agent untouched during preflight. There is no `--force` replacement option.

Dry-run lists proposed directory creation, backups and links without creating anything. Backup IDs shown in preview are examples; execution generates new IDs. Runtime errors stop further setup, but earlier successful integrations remain in place. Rerunning is safe: correct links are skipped. If linking fails after moving a directory, setup attempts to restore it; if another entry occupies the destination, that entry is preserved and the original stays at the printed backup path. This is not a transaction across agents and does not guarantee automatic recovery after a power loss or process termination.

`verify-links` is read-only. It prints `PASS` for correct links, `FAIL` for missing/incorrect/broken links or unsafe paths, and `SKIP` for unselected agents. It returns `0` only if every selected integration passes; conflicts return `1` (invalid CLI arguments return `2`). It needs an existing vault but does not require Watchman, staging jobs or a scanner.

Both commands honor the existing vault configuration:

```bash
python3 agent_skill_gate.py --vault /absolute/physical/path/to/vault setup-links --dry-run
python3 agent_skill_gate.py --vault /absolute/physical/path/to/vault verify-links
```

Managed directories and their ancestors must be real directories, not symlinks; the vault must exist and be separate from backup storage and agent configuration directories. Mutations use directory handles opened without following ancestor links. For custom macOS temporary paths, use `/private/tmp/...` rather than the `/tmp` symlink. Renaming a backup requires the source and backup storage to be on the same filesystem; a cross-device error leaves the source in place. No unsafe copy/delete fallback is used. Do not run setup concurrently with another setup or installer. These checks do not protect against a hostile process with the same user's permissions.

### Backups and restoring original directories

Backups live outside the approved vault:

```text
~/.local/state/agent-skill-gate/backups/
  codex-<UTC timestamp>-<unique ID>/skills/
  claude-<UTC timestamp>-<unique ID>/skills/
```

Each backup slot is created exclusively with owner-only access. A collision is refused rather than reused or overwritten. The `BACKUP` output gives the exact recovery path. There is no automatic backup deletion or blind installation of backed-up skills. `setup-links` only migrates directories; `setup` or `review-backups` separately scans preserved copies and asks about eligible installations. Other discovery paths may still expose skills independently.

To undo a successful setup, first quit the agents and stop installers. Inspect the printed backup and the current link. The following guarded recovery example restores **one Codex directory**; replace `codex-REPLACE-WITH-EXACT-BACKUP-ID` with the actual backup folder name. It refuses to remove anything except the absolute vault link created by setup, refuses occupied restore destinations, and never removes the vault. For Claude, change both `agent` and the backup folder name. Use your original `AGENT_GATE_VAULT` setting if you configured a custom vault.

Run from the repository, with no other process changing these directories:

```bash
python3 - <<'PY'
import os
import stat
from pathlib import Path
from agent_skill_gate import paths
from agent_links import _directory, _entry, _identity, _locations, _restore

agent = "codex"
slot_name = "codex-REPLACE-WITH-EXACT-BACKUP-ID"
if Path(slot_name).name != slot_name or not slot_name.startswith(agent + "-"):
    raise SystemExit("Use the exact backup folder name, without a path")
vault, backups, destinations = _locations(paths()[1], None)
destination = destinations[agent]
backup = backups / slot_name / "skills"
with _directory(backup.parent) as (saved_fd, _), _directory(destination.parent) as (parent_fd, _):
    saved = _entry(saved_fd, "skills")
    if saved is None or not stat.S_ISDIR(saved.st_mode):
        raise SystemExit("Backup is missing or not a real directory; nothing changed")
    current = _entry(parent_fd, "skills")
    if current is not None:
        if not stat.S_ISLNK(current.st_mode) or os.readlink("skills", dir_fd=parent_fd) != str(vault):
            raise SystemExit("Unexpected destination; preserve it and review manually")
        os.unlink("skills", dir_fd=parent_fd)  # Remove only the symlink itself.
    _restore(parent_fd, "skills", saved_fd, _identity(saved))
print(f"Restored {backup} -> {destination}")
PY
```

Restoring the original directory deliberately disconnects that integration from the shared vault, so `verify-links` will then report `FAIL`. If setup was interrupted or a link was changed unexpectedly, preserve both the current entry and backup; inspect with `ls -ld` and `readlink` and resolve manually before retrying. Do not use forced replacement or delete either directory to make verification pass.

### Manually submit previously installed skills

Prefer `review-backups` for guided per-skill decisions. For the unattended `SAFE`-only path, after the scanner is built and available, copy an individual skill from a backup into a fresh folder under staging, preserving symlinks so the gate can reject them. Replace the example backup ID and skill name. Do not run any bundled installer or copy skills directly into the vault:

```bash
# The destination must not exist; exclusive mkdir prevents an accidental merge.
mkdir "$HOME/.agent-staging/build/my-skill" && \
  cp -RP "$HOME/.local/state/agent-skill-gate/backups/codex-EXACT-BACKUP-ID/skills/my-skill/." \
    "$HOME/.agent-staging/build/my-skill/"
python3 agent_skill_gate.py submit "$HOME/.agent-staging/build/my-skill"
python3 agent_skill_gate.py process
python3 agent_skill_gate.py status
```

Review the JSON report under `~/.agent-staging/reports/`. Existing installed names are blocked rather than overwritten; a `CAUTION` or failed scan leaves the submitted snapshot in quarantine and the backup intact. Use your configured staging path if it differs from the default. Project-level skills, plugins, hooks and MCP configurations are separate surfaces and are not covered by these links.

## Scanner and watcher setup

### 1. Initialize storage

Clone/download this repository in any trusted directory **outside** the active skill vault, then:

```bash
python3 agent_skill_gate.py init
```

This creates:

```text
~/.agent-staging/
  .watchmanconfig
  build/           # ALL source downloads and agent-generated skills go here
  incoming/        # sealed submissions: <name>--<unique id>/payload + READY
  processing/      # scanning snapshots
  reviews/         # interactive snapshots; never consumed by Watchman
  quarantine/      # rejected packages
  reports/         # detailed JSON analysis
  logs/events.jsonl
~/.local/share/agent-skills/   # approved skill folders, one level deep
```

### 2. Build and pin the NVIDIA scanner

Choose and review a commit on <https://github.com/NVIDIA/skillspector/commits/main>; pass its **40-character SHA** to the included build script. This pins the scanner you trust. The scanner is built once, **not** downloaded for every submission.

```bash
./scripts/build-scanner.sh <REVIEWED_40_CHARACTER_COMMIT_SHA>
docker image inspect agent-skill-gate-scanner:local >/dev/null
```

Alternatively, use NVIDIA's documented direct Docker build from its cloned repository; tag the result `agent-skill-gate-scanner:local`. The scan invokes `skillspector scan /scan --no-llm --format json --fail-on-incomplete` inside the official image. An offline scan is static-only; no hosted LLM or live OSV API lookups are available from this container.

### 3. Register the Watchman trigger

```bash
python3 agent_skill_gate.py register
python3 agent_skill_gate.py status
```

The registered trigger watches only `READY` events under `incoming/`. It uses absolute paths to Python and the gate script and launches at most one trigger child at a time. The `process` command also supports manual recovery:

```bash
python3 agent_skill_gate.py process
```

The gate resolves the Apple Silicon Homebrew Docker CLI from `/opt/homebrew/bin/docker` even when the Watchman daemon has a minimal `PATH`. Set `AGENT_GATE_DOCKER_BIN` if yours is elsewhere (a custom path must also be available to the watcher).

Watchman persists registered triggers across ordinary server restarts, but can be disabled/unwatched; run `register` again if necessary. Keep this repository in a stable location: the trigger stores an absolute path to the script.

### 4. Test with a minimal harmless skill

```bash
mkdir -p ~/.agent-staging/build/demo-safe
cat > ~/.agent-staging/build/demo-safe/SKILL.md <<'EOF'
---
name: demo-safe
description: Read-only documentation guidance for testing the local install gate.
---
# Demo safe skill
Summarize selected non-sensitive documentation. No scripts or installs required.
EOF
python3 agent_skill_gate.py submit ~/.agent-staging/build/demo-safe
# Watchman should now invoke 'process'; use the next command for deterministic manual recovery:
python3 agent_skill_gate.py process
python3 agent_skill_gate.py status
cat ~/.agent-staging/reports/demo-safe--*.json
ls -ld ~/.local/share/agent-skills/demo-safe
```

The file is installed **only if SkillSpector actually returns `SAFE`**. A `CAUTION` verdict, even with exit code 0, is quarantined by policy.

### 5. Reinstall the Microsoft Foundry skill (real source)

This example pulls a Foundry skill from Microsoft's public repository, **without invoking npm, npm lifecycle scripts, npx, curl-to-shell, or any remote skill setup scripts**:

```bash
git clone --depth 1 https://github.com/microsoft/azure-skills.git \
  ~/.agent-staging/build/microsoft-azure-skills-source
python3 agent_skill_gate.py submit \
  ~/.agent-staging/build/microsoft-azure-skills-source/skills/microsoft-foundry
python3 agent_skill_gate.py process
python3 agent_skill_gate.py status
ls -ld ~/.local/share/agent-skills/microsoft-foundry
```

Microsoft's Foundry skill contains setup instructions and executable scripts; it may **not** receive an automatic `SAFE` verdict. Quarantine is a valid expected outcome, not a failure of the workflow. The gate does not execute those scripts. To test a successful promotion independently, use `demo-safe` first.

Note: Microsoft publishes multiple similarly named Foundry skill collections. The example above chooses the `microsoft/azure-skills` source; verify whether that is the exact edition you previously installed.

## Agent installation contract

Agent system instructions should say: **write all proposed skills under `~/.agent-staging/build/`, never directly to the vault or any active agent skill path, do not run third-party installation scripts; submit completed skill folders using the gate CLI.** A suggested policy is in [docs/AGENT_POLICY.md](docs/AGENT_POLICY.md). This is advisory, **not** an effective permission boundary for an agent that runs as your macOS user.

## Operational CLI

```bash
python3 agent_skill_gate.py init
python3 agent_skill_gate.py setup-links --dry-run
python3 agent_skill_gate.py setup-links
python3 agent_skill_gate.py verify-links
python3 agent_skill_gate.py doctor
python3 agent_skill_gate.py setup
python3 agent_skill_gate.py review-backups
python3 agent_skill_gate.py register
python3 agent_skill_gate.py submit ~/.agent-staging/build/<skill-name>
python3 agent_skill_gate.py process
python3 agent_skill_gate.py status
python3 agent_skill_gate.py unregister
```

Use `AGENT_GATE_STAGING`, `AGENT_GATE_VAULT`, or CLI `--staging/--vault` before the subcommand to configure custom paths. The registered trigger embeds those paths so environment changes do not silently redirect it.

## Unit tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use temporary directories for all skill/link mutations and mock the scanner, notifications and Watchman where needed. They cover link migration, intact backups, rollback, collisions, unsafe paths, dry-run/verification immutability and existing CLI dispatch, as well as scan-first group selection, separate CAUTION consent, malformed/incomplete reports, snapshot integrity during approval, isolated review jobs, quarantine and no-overwrite. Dashboard tests cover legacy JSON export, Markdown escaping, no-overwrite output, Downloads failure fallback, Linux XDG settings and simulated Windows folder lookup. Docker, Watchman, SkillSpector and network access are not needed to run them. Actual scanner/watcher integrations and agent discovery still require an end-to-end test on your Mac.

## Security controls and known gaps

See [docs/SECURITY.md](docs/SECURITY.md). Before calling this an enterprise-class security boundary, enforce a different OS identity for the untrusted agent and a separate vault owner/privileged promotion service; use explicit approval for updates, log verification and periodic inventory checks. Watchman cannot intercept unauthorized writes or prevent filesystem changes.

## References

- [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
- [Watchman triggers](https://facebook.github.io/watchman/docs/cmd/trigger.html)
- [Watchman project watches](https://facebook.github.io/watchman/docs/cmd/watch-project.html)
- [Microsoft Foundry skills](https://github.com/microsoft/azure-skills/tree/main/skills/microsoft-foundry)

## License

MIT; this repository is a reference implementation. NVIDIA SkillSpector remains a separate third-party project with its own license and dependencies.
