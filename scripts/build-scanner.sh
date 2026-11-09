#!/usr/bin/env bash
# Build the OFFICIAL NVIDIA SkillSpector Docker image at an explicit reviewed ref.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "Usage: $0 <reviewed 40-character NVIDIA/skillspector git commit SHA>" >&2
  echo "Find a commit in https://github.com/NVIDIA/skillspector/commits/main" >&2
  exit 2
fi

command -v docker >/dev/null || { echo 'Docker CLI is required' >&2; exit 1; }
command -v git >/dev/null || { echo 'git is required' >&2; exit 1; }
root="${AGENT_GATE_STAGING:-$HOME/.agent-staging}"
mkdir -p "$root/build"
src="$root/build/skillspector-scanner-src"
if [[ -e "$src" ]]; then
  echo "Refusing to reuse existing source directory: $src" >&2
  exit 1
fi

git clone --no-checkout https://github.com/NVIDIA/skillspector.git "$src"
git -C "$src" checkout --detach "$1"
actual="$(git -C "$src" rev-parse HEAD)"
[[ "$actual" == "$1" ]] || { echo 'Commit checkout mismatch' >&2; exit 1; }
printf '%s\n' "$actual" > "$root/build/skillspector-commit.txt"
docker build --pull --tag agent-skill-gate-scanner:local "$src"
echo "Built agent-skill-gate-scanner:local from NVIDIA/skillspector at $actual"
