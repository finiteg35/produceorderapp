# store.py – Thread-safe JSON file store (replaces PostgreSQL + SQLAlchemy)
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
DATA_FILE = DATA_DIR / "app_data.json"

_lock = threading.Lock()


def _default() -> Dict[str, Any]:
    return {
        "inventory": [],
        "orders": [],
        "stores": [],
        "settings": {},
        "_seq": {"inventory": 1, "orders": 1, "stores": 1},
    }


def load() -> Dict[str, Any]:
    if not DATA_FILE.exists():
        return _default()
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Data file {DATA_FILE} is corrupted and could not be parsed: {exc}. "
            "Delete or restore the file to recover."
        ) from exc
    # Forward-compat: ensure all expected keys exist
    default = _default()
    for key in default:
        data.setdefault(key, default[key])
    return data


def save(data: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Atomic write: write to a temp file in the same directory, then replace
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        Path(tmp_path).replace(DATA_FILE)
    except Exception:
        os.unlink(tmp_path)
        raise


def next_id(data: Dict[str, Any], table: str) -> int:
    seq = data["_seq"]
    nid = seq.get(table, 1)
    seq[table] = nid + 1
    return nid


def get_lock() -> threading.Lock:
    return _lock
