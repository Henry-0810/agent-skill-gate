"""Explicit, conservative POSIX setup of agent skill-directory symlinks.

No skill contents are read, executed, merged, or promoted here. Directory-fd
operations avoid following swapped ancestor symlinks. They do not establish a
security boundary against another process with the same user's permissions.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import datetime as dt
import os
from pathlib import Path
import stat
import uuid


AGENT_DIRECTORIES = {"codex": ".agents", "claude": ".claude", "cursor": ".cursor"}
DEFAULT_AGENTS = ("codex", "claude")


def parse_agents(value: str) -> tuple[str, ...]:
    agents = tuple(dict.fromkeys(part.strip() for part in value.split(",")))
    if not agents or any(agent not in AGENT_DIRECTORIES for agent in agents):
        raise ValueError(
            "agents must be a comma-separated selection of codex,claude,cursor"
        )
    return agents


def _absolute(path: Path) -> Path:
    path = path.expanduser().absolute()
    if ".." in path.parts:
        raise ValueError(f"Use an absolute path without '..': {path}")
    return path


@contextlib.contextmanager
def _directory(path: Path, *, create: bool = False, allow_missing: bool = False):
    """Walk from / using O_NOFOLLOW at every component; yield (fd, missing).

    In preview mode, report missing components without creating them. Existing
    directories keep their permissions. Callers must use physical paths (for
    example /private/tmp on macOS rather than the /tmp symlink).
    """
    path = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    missing = []
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current = current / part
            if missing:
                missing.append(current)
                continue
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if create:
                    # A concurrent creator still has to pass the no-follow open.
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=fd)
                elif allow_missing:
                    missing.append(current)
                    continue
                else:
                    raise ValueError(
                        f"Missing directory: {current}; run 'init' first"
                    )
            except OSError as exc:
                raise ValueError(
                    f"Refusing unsafe/non-directory path: {current}: {exc}"
                ) from exc
            os.close(fd)
            fd = child
        yield (None if missing else fd), missing
    finally:
        os.close(fd)


def _entry(parent_fd: int, name: str):
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _identity(info):
    return None if info is None else (info.st_dev, info.st_ino, info.st_mode)


def _overlap(first: Path, second: Path) -> bool:
    if first.is_relative_to(second) or second.is_relative_to(first):
        return True
    # macOS commonly uses case-insensitive filesystems. Lexically different
    # names can refer to the same directory, including an ancestor of a path.
    for root, child in ((first, second), (second, first)):
        try:
            root_info = root.stat(follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if not stat.S_ISDIR(root_info.st_mode):
            continue
        for ancestor in (child, *child.parents):
            try:
                info = ancestor.stat(follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                continue
            if os.path.samestat(root_info, info):
                return True
    return False


def _locations(vault: Path, home: Path | None):
    home = _absolute(home if home is not None else Path.home())
    vault = _absolute(vault)
    backup_root = home / ".local" / "state" / "agent-skill-gate" / "backups"
    destinations = {
        agent: home / directory / "skills"
        for agent, directory in AGENT_DIRECTORIES.items()
    }
    if _overlap(vault, backup_root):
        raise ValueError(
            "Vault and backup storage must be separate, non-overlapping directories"
        )
    for path in destinations.values():
        if _overlap(vault, path.parent):
            raise ValueError(
                "Vault must not overlap an agent configuration directory: "
                f"{path.parent}"
            )
    with _directory(home), _directory(vault):
        pass
    return vault, backup_root, destinations


@dataclass(frozen=True)
class _Plan:
    agent: str
    path: Path
    kind: str
    detail: str
    identity: tuple | None


def _inspect(agent: str, path: Path, vault: Path) -> _Plan:
    with _directory(path.parent, allow_missing=True) as (fd, _):
        info = None if fd is None else _entry(fd, path.name)
        identity = _identity(info)
        if info is None:
            return _Plan(agent, path, "missing", "skills path is missing", identity)
        if stat.S_ISLNK(info.st_mode):
            destination = Path(os.readlink(path.name, dir_fd=fd))
            if not destination.is_absolute():
                destination = path.parent / destination
            try:
                resolved = destination.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                return _Plan(
                    agent, path, "conflict",
                    f"broken/unresolvable link -> {destination}: {exc}", identity,
                )
            if resolved.samefile(vault):
                return _Plan(agent, path, "linked", f"already linked -> {vault}", identity)
            return _Plan(
                agent, path, "conflict",
                f"unexpected link -> {resolved}; preserve it and recover manually",
                identity,
            )
        if stat.S_ISDIR(info.st_mode):
            return _Plan(
                agent, path, "directory",
                "existing directory requires a separate backup", identity,
            )
        return _Plan(
            agent, path, "conflict",
            "existing file or special filesystem object; refusing replacement",
            identity,
        )


def _plans(vault: Path, destinations: dict, agents: tuple[str, ...]):
    plans = []
    for agent in agents:
        try:
            plans.append(_inspect(agent, destinations[agent], vault))
        except (OSError, ValueError) as exc:
            plans.append(_Plan(agent, destinations[agent], "conflict", str(exc), None))
    return plans


def _selection(agents: tuple[str, ...], *, quiet: bool = False) -> tuple[str, ...]:
    selected = parse_agents(",".join(agents))
    for agent in AGENT_DIRECTORIES:
        if agent not in selected and not quiet:
            print(f"SKIP {agent}: not selected")
    return selected


def verify_links(
    vault: Path,
    agents: tuple[str, ...] = DEFAULT_AGENTS,
    *,
    home: Path | None = None,
    quiet: bool = False,
) -> int:
    """Read-only verification; every selected integration is required."""
    try:
        agents = _selection(agents, quiet=quiet)
    except (OSError, ValueError) as exc:
        print(f"FAIL verify-links: {exc}")
        return 1
    try:
        vault, _, destinations = _locations(vault, home)
    except (OSError, ValueError) as exc:
        for agent in agents:
            print(f"FAIL {agent}: cannot verify links: {exc}")
        return 1
    failed = False
    for plan in _plans(vault, destinations, agents):
        passed = plan.kind == "linked"
        label = "PASS" if passed else "FAIL"
        if not passed or not quiet:
            print(f"{label} {plan.agent}: {plan.path}: {plan.detail}")
        failed |= not passed
    return int(failed)


def _backup_name(agent: str) -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{agent}-{timestamp}-{uuid.uuid4().hex}"


def _restore(parent_fd: int, name: str, backup_fd: int, identity: tuple) -> None:
    """Reserve an absent destination before renaming the saved directory back.

    mkdir is exclusive: a destination created after the failed link operation
    is preserved, including dangling symlinks. Never replace an occupied path.
    """
    if _identity(_entry(backup_fd, "skills")) != identity:
        raise RuntimeError("backup changed; manual recovery required")
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    reservation = _identity(_entry(parent_fd, name))
    try:
        if _identity(_entry(parent_fd, name)) != reservation:
            raise RuntimeError(
                "restore destination changed; manual recovery required"
            )
        os.rename("skills", name, src_dir_fd=backup_fd, dst_dir_fd=parent_fd)
    except Exception:
        if _identity(_entry(parent_fd, name)) == reservation:
            # rmdir cannot remove a nonempty directory or follow a symlink.
            with contextlib.suppress(OSError):
                os.rmdir(name, dir_fd=parent_fd)
        raise


def _apply(plan: _Plan, vault: Path, backup_root: Path) -> None:
    with _directory(plan.path.parent, create=True) as (parent_fd, _):
        if _identity(_entry(parent_fd, plan.path.name)) != plan.identity:
            raise RuntimeError(
                f"Destination changed since preflight: {plan.path}; rerun preview"
            )
        if plan.kind == "missing":
            os.symlink(str(vault), plan.path.name, dir_fd=parent_fd)
            print(f"LINK {plan.agent}: {plan.path} -> {vault}")
            return
        with _directory(backup_root, create=True) as (root_fd, _):
            slot = _backup_name(plan.agent)
            # Exclusive mkdir refuses collisions, even an empty preexisting slot.
            os.mkdir(slot, mode=0o700, dir_fd=root_fd)
            backup = backup_root / slot / "skills"
            with _directory(backup.parent) as (backup_fd, _):
                if _entry(backup_fd, "skills") is not None:
                    raise RuntimeError(f"Backup destination already exists: {backup}")
                if _identity(_entry(parent_fd, plan.path.name)) != plan.identity:
                    raise RuntimeError(
                        f"Source changed before backup: {plan.path}; refusing to move it"
                    )
                # No cross-device fallback: a failed rename leaves source intact.
                os.rename(
                    plan.path.name, "skills",
                    src_dir_fd=parent_fd, dst_dir_fd=backup_fd,
                )
                print(f"BACKUP {plan.agent}: {plan.path} -> {backup}")
                if _identity(_entry(backup_fd, "skills")) != plan.identity:
                    raise RuntimeError(
                        f"Source changed during backup; preserved at {backup}; "
                        "manual recovery required"
                    )
                try:
                    os.symlink(str(vault), plan.path.name, dir_fd=parent_fd)
                except OSError as exc:
                    try:
                        _restore(
                            parent_fd, plan.path.name, backup_fd, plan.identity
                        )
                    except Exception as restore_error:
                        raise RuntimeError(
                            f"Link creation failed: {exc}; original preserved at {backup}; "
                            f"could not restore safely: {restore_error}"
                        ) from exc
                    print(
                        f"RESTORED {plan.agent}: original directory at {plan.path}"
                    )
                    with contextlib.suppress(OSError):
                        os.rmdir(slot, dir_fd=root_fd)
                    raise RuntimeError(
                        f"Link creation failed; original directory restored: {exc}"
                    ) from exc
            print(f"LINK {plan.agent}: {plan.path} -> {vault}")


def setup_links(
    vault: Path,
    agents: tuple[str, ...] = DEFAULT_AGENTS,
    *,
    dry_run: bool = False,
    home: Path | None = None,
    quiet: bool = False,
) -> int:
    """Preflight all selected paths, then apply per-agent backup/link operations.

    No cross-agent transaction is promised: a later I/O failure can leave earlier
    agents linked. A rerun skips those links. Dry-run never creates even a lock.
    """
    try:
        agents = _selection(agents, quiet=quiet)
        vault, backup_root, destinations = _locations(vault, home)
        plans = _plans(vault, destinations, agents)
        if any(plan.kind == "directory" for plan in plans):
            with _directory(backup_root, allow_missing=True):
                pass
    except (OSError, ValueError) as exc:
        print(f"FAIL setup-links: {exc}; no links changed")
        return 1
    if any(plan.kind == "conflict" for plan in plans):
        for plan in plans:
            label = "FAIL" if plan.kind == "conflict" else "SKIP"
            print(f"{label} {plan.agent}: {plan.path}: {plan.detail}")
        print(
            "Preflight failed; no links changed. "
            "Resolve conflicts manually, then rerun --dry-run."
        )
        return 1
    if dry_run:
        print(
            "DRY-RUN: no filesystem changes; "
            "generated backup IDs will differ on execution."
        )
    failed = False
    for plan in plans:
        if plan.kind == "linked":
            if not quiet:
                print(f"SKIP {plan.agent}: {plan.path}: {plan.detail}")
            continue
        if dry_run:
            with _directory(plan.path.parent, allow_missing=True) as (_, missing):
                for path in missing:
                    print(f"WOULD MKDIR {path} (mode 700)")
            if plan.kind == "directory":
                slot_name = _backup_name(plan.agent)
                with _directory(backup_root, allow_missing=True) as (fd, missing):
                    if fd is not None and _entry(fd, slot_name) is not None:
                        print(f"FAIL {plan.agent}: backup slot already exists: {backup_root / slot_name}")
                        return 1
                    for path in missing:
                        print(f"WOULD MKDIR {path} (mode 700)")
                slot = backup_root / slot_name
                print(f"WOULD MKDIR {slot} (exclusive, mode 700)")
                print(f"WOULD BACKUP {plan.path} -> {slot / 'skills'}")
            print(f"WOULD LINK {plan.agent}: {plan.path} -> {vault}")
            continue
        try:
            # Revalidate the vault path before each mutation as well as preflight.
            with _directory(vault):
                _apply(plan, vault, backup_root)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"FAIL {plan.agent}: {exc}")
            failed = True
            break
    if failed:
        print(
            "Setup stopped; earlier successful links/backups are retained. "
            "Rerun --dry-run before retrying."
        )
    return int(failed)
