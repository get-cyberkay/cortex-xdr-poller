import atexit
import logging
import os
import queue
import sys
from logging.handlers import QueueHandler, QueueListener, TimedRotatingFileHandler

from config import (
    ENABLE_FILE_LOG,
    LOG_DIR, INCIDENTS_LOG_DIR, AUDIT_MGMT_LOG_DIR,
    AUDIT_AGENT_LOG_DIR, OPS_LOG_DIR,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
)

# ---------------------------------------------------------------------------
# Async listener registry — stopped at process exit to flush all queues.
# ---------------------------------------------------------------------------
_listeners: list[QueueListener] = []


@atexit.register
def _stop_all_listeners() -> None:
    """Drain and stop every QueueListener before the process exits."""
    for listener in _listeners:
        try:
            listener.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Custom handler: daily rotation + 100 MB size cap
# ---------------------------------------------------------------------------

class _SizedTimedRotatingFileHandler(TimedRotatingFileHandler):
    """
    TimedRotatingFileHandler extended with a size cap.
    Rotates when the file reaches max_bytes regardless of whether the daily
    interval has elapsed. Size check runs first.
    """

    def __init__(self, filename: str, max_bytes: int, **kwargs):
        super().__init__(filename, **kwargs)
        self.max_bytes = max_bytes

    def shouldRollover(self, record) -> bool:  # noqa: N802
        try:
            if self.stream and self.max_bytes > 0:
                self.stream.seek(0, 2)
                if self.stream.tell() >= self.max_bytes:
                    return True
        except OSError as exc:
            sys.stderr.write(
                f"[ERROR] _SizedTimedRotatingFileHandler.shouldRollover: "
                f"failed to check file size for {self.baseFilename!r}: {exc}\n"
            )
        return super().shouldRollover(record)


# ---------------------------------------------------------------------------
# Level-filter helpers
# ---------------------------------------------------------------------------

class _MaxLevelFilter(logging.Filter):
    """Passes only records at or below max_level (inclusive)."""
    def __init__(self, max_level: int):
        super().__init__()
        self.max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.max_level


class _MinLevelFilter(logging.Filter):
    """Passes only records at or above min_level (inclusive)."""
    def __init__(self, min_level: int):
        super().__init__()
        self.min_level = min_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.min_level


# ---------------------------------------------------------------------------
# Handler factory
# ---------------------------------------------------------------------------

def _make_file_handler(log_dir: str, filename: str) -> _SizedTimedRotatingFileHandler:
    """
    Build a sized+timed rotating file handler.
    Creates the target directory automatically if it does not exist.
    Raises OSError with context if directory or file cannot be opened.
    """
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError as exc:
        raise OSError(
            f"_make_file_handler: could not create log directory {log_dir!r}: {exc}"
        ) from exc

    try:
        return _SizedTimedRotatingFileHandler(
            filename    = os.path.join(log_dir, filename),
            max_bytes   = LOG_MAX_BYTES,
            when        = "midnight",
            interval    = 1,
            backupCount = LOG_BACKUP_COUNT,
            utc         = True,
        )
    except OSError as exc:
        raise OSError(
            f"_make_file_handler: could not open log file "
            f"{os.path.join(log_dir, filename)!r}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

_TS_FMT  = "%Y-%m-%dT%H:%M:%SZ"
_OPS_FMT = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt=_TS_FMT
)
_LEEF_FMT = logging.Formatter("%(message)s")


# ---------------------------------------------------------------------------
# LEEF logger factory
# ---------------------------------------------------------------------------

def _make_async_handler(fh: logging.Handler) -> QueueHandler:
    """
    Wrap a synchronous handler in an async QueueHandler + QueueListener pair.

    The returned QueueHandler enqueues records instantly (non-blocking).
    A background daemon thread (QueueListener) drains the queue and calls
    the real handler.  The listener is registered in _listeners so it is
    gracefully stopped (queue drained) at process exit.
    """
    log_queue: queue.Queue = queue.Queue(-1)   # unbounded
    listener = QueueListener(log_queue, fh, respect_handler_level=True)
    listener.start()
    _listeners.append(listener)
    return QueueHandler(log_queue)


def _make_leef_logger(name: str, log_dir: str, filename: str) -> logging.Logger:
    """
    Build a LEEF output logger with an async rotating file handler.
    Falls back to NullHandler if ENABLE_FILE_LOG=false or if the handler
    cannot be created, writing the failure reason to stderr.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not ENABLE_FILE_LOG:
        logger.addHandler(logging.NullHandler())
        return logger

    try:
        fh = _make_file_handler(log_dir, filename)
        fh.setFormatter(_LEEF_FMT)
        logger.addHandler(_make_async_handler(fh))
    except OSError as exc:
        sys.stderr.write(
            f"[ERROR] _make_leef_logger: failed to create file handler for "
            f"logger {name!r} ({log_dir}/{filename}): {exc}. "
            f"File output for this stream will be DISABLED.\n"
        )
        logger.addHandler(logging.NullHandler())

    return logger


# ---------------------------------------------------------------------------
# LEEF loggers — one per data stream
# ---------------------------------------------------------------------------

alerts_leef_log      = _make_leef_logger("cortex_alerts",      LOG_DIR,             "cortex_alerts.log")
incidents_leef_log   = _make_leef_logger("cortex_incidents",   INCIDENTS_LOG_DIR,   "cortex_incidents.log")
mgmt_audit_leef_log  = _make_leef_logger("cortex_mgmt_audit",  AUDIT_MGMT_LOG_DIR,  "cortex_mgmt_audit.log")
agent_audit_leef_log = _make_leef_logger("cortex_agent_audit", AUDIT_AGENT_LOG_DIR, "cortex_agent_audit.log")


# ---------------------------------------------------------------------------
# Operational logger
#
# Two separate rotating files in OPS_LOG_DIR:
#   cortex_info.log  — INFO level only  (routine operational messages)
#   cortex_error.log — WARNING + ERROR  (failures, anomalies, warnings)
#
# stderr receives all levels (for service managers / Docker / systemd).
# ---------------------------------------------------------------------------

log = logging.getLogger("cortex_poller")
log.setLevel(logging.DEBUG)   # let handlers decide their own level cutoff
log.propagate = False

# -- INFO-only file handler (async) --
try:
    _info_fh = _make_file_handler(OPS_LOG_DIR, "cortex_info.log")
    _info_fh.setFormatter(_OPS_FMT)
    _info_fh.setLevel(logging.INFO)
    _info_fh.addFilter(_MaxLevelFilter(logging.INFO))   # INFO only, not WARNING/ERROR
    log.addHandler(_make_async_handler(_info_fh))
except OSError as exc:
    sys.stderr.write(
        f"[ERROR] logging_setup: failed to create info log handler "
        f"({OPS_LOG_DIR}/cortex_info.log): {exc}. "
        f"INFO logs will only go to stderr.\n"
    )

# -- WARNING + ERROR file handler (async) --
try:
    _error_fh = _make_file_handler(OPS_LOG_DIR, "cortex_error.log")
    _error_fh.setFormatter(_OPS_FMT)
    _error_fh.setLevel(logging.WARNING)                 # WARNING and above only
    log.addHandler(_make_async_handler(_error_fh))
except OSError as exc:
    sys.stderr.write(
        f"[ERROR] logging_setup: failed to create error log handler "
        f"({OPS_LOG_DIR}/cortex_error.log): {exc}. "
        f"ERROR logs will only go to stderr.\n"
    )

# -- stderr: all levels --
_stderr_h = logging.StreamHandler(sys.stderr)
_stderr_h.setFormatter(_OPS_FMT)
_stderr_h.setLevel(logging.DEBUG)
log.addHandler(_stderr_h)
