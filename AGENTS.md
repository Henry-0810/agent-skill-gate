# Contributor instructions

## Orientation

- Read `docs/HANDOFF.md` for current status and next work, `docs/ARCHITECTURE.md` for implemented flows and trust boundaries, and `docs/SECURITY.md` before changing security behavior.
- Target Python 3.10+ and macOS/POSIX. The gate uses `fcntl` and POSIX directory/file operations; portable report-path helpers do not establish native Windows support.
- Reuse the existing standard-library implementation and `unittest` conventions. Add dependencies only when necessary and explain why.

## Changes and validation

- Inspect `git status` before editing and preserve pre-existing changes. Do not commit, push, reset, or clean the working tree unless requested.
- Keep changes within the requested scope. Do not change scanner policy or broaden permissions as a side effect of a UI/integration change.
- Run `python3 -B -m unittest discover -s tests -v` for behavioral changes. Use physical temporary paths (`Path(...).resolve()`) in filesystem tests because macOS `/var` and `/tmp` may be symlinks.
- Unit tests must use temporary profiles and mock Docker, Watchman and notifications. Label simulated scans explicitly; distinguish tests using mocks from actual backend/event-delivery validation.
- For interactive development use `python3 agent_skill_gate.py setup --demo`. Real-scanner demo mode needs Docker and a trusted local scanner image; it must still use harmless temporary samples and leave Watchman disabled.

## Safety and product contracts

- Do not test migration, cleanup, permission changes, or installation against the developer's real home-directory skills, vault, backups or staging. Use isolated profiles. Export to real Downloads only when requested.
- Never delete or merge existing skills to reset tests. Preserve backup originals and saved JSON evidence. Do not overwrite user report files or existing installed names.
- Resolve paths from configuration and the user's home; do not hardcode a developer username into application behavior.
- Keep automatic installs SAFE-only. Interactive CAUTION acceptance must remain explicit and recorded; incomplete/error/high-risk results cannot be approved. Reuse `agent_review.scan_problem` and the snapshot/promotion checks rather than adding a second verdict policy.
- Do not execute submitted skill code or installer hooks. Do not silently replace isolated scanning with unrestricted host execution when a dependency is unavailable.
- Keep interactive review jobs separate from the `READY` queue. Preserve default-No behavior for remaining selections and CAUTION acceptance; never let the model forge human approval.
- Treat scan text as untrusted in terminal and Markdown output. A risk score, dashboard, symlink, routing instruction or MCP tool is not an OS-enforced boundary.
- A skill installation is not a generic software installation: supported managed skill paths are the scope, and other agent/plugin/project discovery paths need explicit treatment before making broader claims.
