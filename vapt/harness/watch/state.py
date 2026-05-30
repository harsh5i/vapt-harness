"""Watch + queue state primitives: locations of the watch root, per-target
profiles, polling state, the runtime queue, and atomic queue-entry writes.

`queue_write_entry` is the only sanctioned path for appending a queue entry —
it locks the per-target queue directory and stamps the schema version, queue id,
status, and history before any caller sees it.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

import datetime as dt
import re
import uuid
from pathlib import Path
from typing import Any

from atomic_io import dump_yaml, file_lock, load_yaml, read_json, write_json
from core import ROOT


def watches_dir() -> Path:
    return ROOT / "vapt" / "harness" / "watches"


def watch_state_dir() -> Path:
    return watches_dir() / "state"


def queue_dir() -> Path:
    return ROOT / "vapt" / "harness" / "queue"


def watch_profile_path(target_id: str) -> Path:
    return watches_dir() / f"{target_id}.yaml"


def load_watch_profiles(target_id: str | None = None) -> list[dict[str, Any]]:
    profiles = []
    paths = [watch_profile_path(target_id)] if target_id else sorted(watches_dir().glob("*.yaml"))
    for path in paths:
        if not path.exists() or path.parent.name == "state":
            continue
        profile = load_yaml(path) or {}
        profile.setdefault("target_id", path.stem)
        profile.setdefault("sources", [])
        profile.setdefault("poll_interval_minutes", 30)
        profile.setdefault("trigger_patterns", [])
        profile["_path"] = path
        profiles.append(profile)
    return profiles


def load_watch_state(target_id: str) -> dict[str, Any]:
    return read_json(watch_state_dir() / f"{target_id}.json", {"target_id": target_id, "sources": {}})


def save_watch_state(target_id: str, state: dict[str, Any]) -> None:
    state["target_id"] = target_id
    state["updated_at"] = dt.datetime.now().isoformat(timespec="seconds")
    write_json(watch_state_dir() / f"{target_id}.json", state)


def watch_source_key(source: dict[str, Any]) -> str:
    parts = [
        str(source.get("kind", "")),
        str(source.get("repo") or source.get("repo_path") or ""),
        str(source.get("branch") or ""),
        str(source.get("package") or ""),
        str(source.get("ecosystem") or ""),
        str(source.get("fixture") or ""),
    ]
    return "|".join(parts)


def queue_entry_path(target_id: str, queue_id: str) -> Path:
    raw = queue_id.split("/", 1)[1] if "/" in queue_id else queue_id
    return queue_dir() / target_id / f"{raw}.yaml"


def queue_write_entry(target_id: str, entry: dict[str, Any]) -> Path:
    queue_root = queue_dir() / target_id
    queue_root.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    ref = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(entry.get("ref") or entry.get("source_key") or "event"))[:48]
    queue_id = f"{stamp}_{ref}_{uuid.uuid4().hex[:8]}"
    entry["schema_version"] = 1
    entry["queue_id"] = f"{target_id}/{queue_id}"
    entry.setdefault("target_id", target_id)
    entry.setdefault("status", "pending")
    entry.setdefault("created_at", dt.datetime.now().isoformat(timespec="seconds"))
    entry.setdefault("history", []).append(
        {"at": dt.datetime.now().isoformat(timespec="seconds"), "event": "queued"}
    )
    path = queue_root / f"{queue_id}.yaml"
    with file_lock(queue_root / ".queue"):
        dump_yaml(entry, path)
    return path


def queue_entries(target_id: str | None = None, include_claimed: bool = False) -> list[dict[str, Any]]:
    roots = [queue_dir() / target_id] if target_id else sorted(queue_dir().glob("*"))
    rows = []
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for path in sorted(root.glob("*.yaml")):
            entry = load_yaml(path) or {}
            entry["_path"] = path
            if include_claimed or entry.get("status", "pending") == "pending":
                rows.append(entry)
    return rows
