import json
import os
import threading

from config import STATE_FILE
from logging_setup import log

# Serialises concurrent save_state calls from different stream threads.
_save_lock = threading.Lock()


def load_state() -> dict:
    """
    Return persisted state from STATE_FILE, or an empty dict if the file
    does not exist or cannot be parsed.
    """
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read state file (%s). Starting fresh.", exc)
        return {}


def save_state(state: dict) -> None:
    """
    Persist state to STATE_FILE atomically using a write-then-rename pattern.
    A partial write will never corrupt the existing state file.
    Thread-safe: concurrent calls are serialised by _save_lock.
    """
    tmp = STATE_FILE + ".tmp"
    with _save_lock:
        try:
            with open(tmp, "w") as f:
                json.dump(state, f)
            os.replace(tmp, STATE_FILE)
        except OSError as exc:
            log.error("Failed to save state file: %s", exc)
