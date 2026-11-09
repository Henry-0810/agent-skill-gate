# Suggested agent instruction (advisory, not a sandbox)

Use this policy in the tools' corresponding *trusted* global or project instructions. Do not rely on it as a filesystem access-control mechanism.

> **Third-party agent-skill installation policy**
>
> Never download, generate, unpack, move, symlink, or install a skill into `~/.local/share/agent-skills`, `~/.agents/skills`, `~/.claude/skills`, or `~/.cursor/skills`. Do not call `npx skills add`, `npm install`, `curl | sh`, `brew install`, or a third-party skill setup script to install an unreviewed skill. Prepare only raw skill source files inside `~/.agent-staging/build/<skill-name>/`. Do not execute skill code or its dependency install hooks during preparation. Once the skill folder contains `SKILL.md` and is complete, submit it with `python3 <TRUSTED_GATE_REPO>/agent_skill_gate.py submit ~/.agent-staging/build/<skill-name>`. Let the trusted Watchman gate choose promotion/quarantine. Never modify the gate, scanner config, vault, report or quarantine to force approval. If a skill requests credentials, privilege escalation, additional runtime downloads or unexpected system modifications, ask for review before use.

Limitations: These instructions cannot prevent a malicious prompt injection or compromised agent process from writing outside the stage. They are intended to steer normal, cooperative agent behavior only.

Human setup/review is separate from this agent contract. A human may run `setup` or `review-backups` to inspect results and explicitly accept a `CAUTION` result. Agents should not use those commands to approve their own proposed skills, synthesize approval input, suppress findings, or treat a risk score as proof of safe execution. Watchman remains `SAFE`-only.
