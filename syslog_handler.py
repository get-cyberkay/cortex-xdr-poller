"""
syslog_handler.py — RFC 5424 syslog sender (TCP or UDP, best-effort).

Public interface
----------------
send_syslog(msg: str, app_name: str) -> None
    Format msg as an RFC 5424 frame and dispatch it to the configured
    syslog server. On any failure the error is logged to the ops logger
    and the function returns silently — callers are never interrupted.

Design notes
------------
- TCP: a single module-level socket is reused across calls. On any send
  failure it is closed and a fresh connection is attempted immediately.
  If reconnection also fails the message is dropped and the error is logged.
- UDP: stateless sendto on every call — no persistent socket needed.
- RFC 5424 severity is always INFO (6). Priority = facility*8 + severity.
- STRUCTURED-DATA is set to "-" (nil) — LEEF lines carry all field data.
- HOSTNAME is the local machine hostname, truncated to 255 chars per spec.
- PROCID is the current process ID.
"""

import atexit
import os
import queue
import socket
import threading
from datetime import datetime, timezone

from config import (
    ENABLE_SYSLOG,
    SYSLOG_HOST, SYSLOG_PORT,
    SYSLOG_TRANSPORT, SYSLOG_FACILITY, SYSLOG_TCP_FRAMING,
    SYSLOG_MAX_MSG_BYTES,
)
from logging_setup import log


# ---------------------------------------------------------------------------
# RFC 5424 constants
# ---------------------------------------------------------------------------
_SEVERITY_INFO = 6          # informational
_NILVALUE      = "-"        # RFC 5424 nil value for optional fields
_VERSION       = "1"        # RFC 5424 version is always 1
_HOSTNAME      = socket.gethostname()[:255]
_PROCID        = str(os.getpid())
_MSGID         = _NILVALUE  # no per-message ID needed


# ---------------------------------------------------------------------------
# TCP socket state — one persistent connection reused by the worker thread.
# No external locking needed: only _syslog_worker() touches the socket.
# ---------------------------------------------------------------------------
_tcp_socket: socket.socket | None = None


# ---------------------------------------------------------------------------
# Async send queue + worker thread
#
# send_syslog() enqueues (msg, app_name) tuples immediately and returns.
# _syslog_worker() runs in a background thread, formats RFC 5424 frames,
# and dispatches them to TCP/UDP without blocking callers.
#
# Shutdown: atexit calls _shutdown_syslog_worker() which enqueues a None
# sentinel and joins the thread (up to 10 s) so in-flight messages are sent.
# ---------------------------------------------------------------------------
_syslog_queue: queue.Queue = queue.Queue(-1)   # unbounded


def _syslog_worker() -> None:
    while True:
        item = _syslog_queue.get()
        try:
            if item is None:   # sentinel — clean shutdown
                return
            msg, app_name = item
            try:
                frame = _format_rfc5424(msg, app_name)
                if SYSLOG_TRANSPORT == "udp":
                    _send_udp(frame)
                else:
                    _send_tcp(frame)
            except Exception as exc:   # noqa: BLE001
                log.error("Unexpected error in syslog worker: %s", exc)
        finally:
            _syslog_queue.task_done()


_syslog_thread = threading.Thread(
    target=_syslog_worker, name="syslog-worker", daemon=True,
)
_syslog_thread.start()


@atexit.register
def _shutdown_syslog_worker() -> None:
    """Drain the syslog queue and stop the worker thread before process exit."""
    _syslog_queue.put(None)           # wake up worker with sentinel
    _syslog_thread.join(timeout=10)   # wait at most 10 s for clean drain


def _priority() -> int:
    """Compute RFC 5424 PRI value: facility * 8 + severity."""
    return SYSLOG_FACILITY * 8 + _SEVERITY_INFO


def _format_rfc5424(msg: str, app_name: str) -> bytes:
    """
    Build a complete RFC 5424 syslog message as UTF-8 bytes.

    Format:
      <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

    TCP framing defaults to octet-counting (RFC 6587 §3.4.1):
      MSG-LEN SP SYSLOG-MSG
    Some receivers expect newline-delimited TCP syslog instead; set
    SYSLOG_TCP_FRAMING=newline for that mode.
    UDP sends the raw message without framing.
    """
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    header = (
        f"<{_priority()}>{_VERSION} {timestamp} {_HOSTNAME} "
        f"{app_name[:48]} {_PROCID} {_MSGID} {_NILVALUE}"
    )
    full_msg = f"{header} {msg}"
    encoded  = full_msg.encode("utf-8", errors="replace")

    if len(encoded) > SYSLOG_MAX_MSG_BYTES:
        marker        = b" [TRUNCATED]"
        header_bytes  = f"{header} ".encode("utf-8")
        budget        = SYSLOG_MAX_MSG_BYTES - len(header_bytes) - len(marker)
        encoded       = header_bytes + msg.encode("utf-8", errors="replace")[:budget] + marker
        log.warning(
            "syslog: message truncated to %d bytes (app=%s).",
            len(encoded), app_name,
        )

    if SYSLOG_TRANSPORT == "tcp":
        if SYSLOG_TCP_FRAMING == "newline":
            return encoded + b"\n"
        # Octet-count framing per RFC 6587.
        return f"{len(encoded)} ".encode() + encoded
    else:
        return encoded


def _send_tcp(frame: bytes) -> None:
    """Send a pre-framed message over the persistent TCP socket.

    Called only from _syslog_worker() — no locking needed.
    """
    global _tcp_socket

    def _connect() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Use a short timeout for connect, then return to blocking mode so
        # large framed sends are not dropped mid-transfer on slow receivers.
        s.settimeout(5)
        s.connect((SYSLOG_HOST, SYSLOG_PORT))
        s.settimeout(None)
        return s

    # Attempt send; on failure close, reconnect once, retry once.
    for attempt in range(2):
        try:
            if _tcp_socket is None:
                _tcp_socket = _connect()
            _tcp_socket.sendall(frame)
            return
        except OSError as exc:
            log.error(
                "Syslog TCP send failed (attempt %d/2, %s:%d): %s",
                attempt + 1, SYSLOG_HOST, SYSLOG_PORT, exc,
            )
            try:
                if _tcp_socket:
                    _tcp_socket.close()
            except OSError:
                pass
            _tcp_socket = None

    log.error(
        "Syslog TCP: message dropped after 2 failed attempts (%s:%d).",
        SYSLOG_HOST, SYSLOG_PORT,
    )


def _send_udp(frame: bytes) -> None:
    """Send a datagram to the syslog server. Stateless — no persistent socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(frame, (SYSLOG_HOST, SYSLOG_PORT))
    except OSError as exc:
        log.error(
            "Syslog UDP send failed (%s:%d): %s",
            SYSLOG_HOST, SYSLOG_PORT, exc,
        )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def send_syslog(msg: str, app_name: str) -> None:
    """
    Enqueue msg for async RFC 5424 delivery to the configured syslog server.

    Returns immediately — the background worker thread formats and sends the
    message without blocking the caller.
    No-op if ENABLE_SYSLOG is False or SYSLOG_HOST is not set.
    Never raises.
    """
    if not ENABLE_SYSLOG:
        return

    if not SYSLOG_HOST:
        log.warning(
            "ENABLE_SYSLOG=true but SYSLOG_HOST is not set. "
            "Syslog output is disabled until SYSLOG_HOST is configured."
        )
        return

    _syslog_queue.put((msg, app_name))
