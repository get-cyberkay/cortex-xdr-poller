"""
syslog_handler.py — raw log sender over TCP or UDP (best-effort).

Public interface
----------------
send_syslog(msg: str, app_name: str) -> None
    Encode msg as UTF-8, apply TCP framing if needed, and dispatch it to
    the configured syslog server.  By default the formatted log line is sent
    as-is — LEEF, CEF, and JSON payloads are self-describing and carry all
    required event metadata internally.  When SYSLOG_HOSTNAME is set, a minimal
    RFC 3164 header (`<PRI>TIMESTAMP HOSTNAME `) is prepended so the SIEM can
    use that hostname as the Log Source Identifier.

    On any failure the error is logged to the ops logger and the function
    returns silently — callers are never interrupted.

Design notes
------------
- TCP: a single module-level socket is reused across calls. On any send
  failure it is closed and a fresh connection is attempted immediately.
  If reconnection also fails the message is dropped and the error is logged.
  Framing: newline-delimited (default) or RFC 6587 octet-count.
- UDP: one datagram per call — each sendto() delivers exactly one log line.
- Encoding: UTF-8 throughout; non-encodable characters replaced.
"""

import atexit
import queue
import socket
import threading
from datetime import datetime, timedelta, timezone

from config import (
    ENABLE_SYSLOG,
    SYSLOG_HOST, SYSLOG_PORT,
    SYSLOG_TRANSPORT, SYSLOG_TCP_FRAMING,
    SYSLOG_MAX_MSG_BYTES,
    SYSLOG_HOSTNAME, SYSLOG_FACILITY,
    DISPLAY_TZ_OFFSET,
)
from logging_setup import log


# RFC 3164 PRI = facility * 8 + severity. Severity 6 = informational.
_SYSLOG_PRI = SYSLOG_FACILITY * 8 + 6


def _rfc3164_header() -> str:
    """Build an RFC 3164 syslog header: ``<PRI>Mmm dd hh:mm:ss HOSTNAME ``.

    Returns an empty string when SYSLOG_HOSTNAME is not configured, so the raw
    payload is sent unchanged (preserving the default headerless behaviour).

    The HOSTNAME field is what QRadar uses as the Log Source Identifier. The
    timestamp uses DISPLAY_TZ_OFFSET for consistency with the payload's event
    times; SIEMs take event time from the LEEF/CEF body, not this header.
    """
    if not SYSLOG_HOSTNAME:
        return ""
    now = datetime.now(timezone.utc) + timedelta(hours=DISPLAY_TZ_OFFSET)
    # RFC 3164 requires the day to be space-padded to width 2 (e.g. "Jun  8").
    ts = f"{now:%b} {now.day:2d} {now:%H:%M:%S}"
    return f"<{_SYSLOG_PRI}>{ts} {SYSLOG_HOSTNAME} "


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
_SYSLOG_QUEUE_MAXSIZE = 10_000
_syslog_queue: queue.Queue = queue.Queue(_SYSLOG_QUEUE_MAXSIZE)


def _syslog_worker() -> None:
    while True:
        item = _syslog_queue.get()
        try:
            if item is None:   # sentinel — clean shutdown
                return
            msg, app_name = item
            try:
                frame = _prepare_payload(msg, app_name)
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


def _prepare_payload(msg: str, app_name: str) -> bytes:
    """
    Optionally prepend an RFC 3164 header, encode as UTF-8, and apply framing.

    When SYSLOG_HOSTNAME is set, a ``<PRI>TIMESTAMP HOSTNAME `` header is
    prepended so the SIEM can derive a stable Log Source Identifier from the
    hostname. When it is empty (default) the LEEF/CEF/JSON payload is sent
    as-is — it carries all required event metadata internally.

    TCP framing:
      newline (default) → MSG LF         (line-delimited, QRadar/Splunk)
      octet             → MSG-LEN SP MSG (RFC 6587, rsyslog/syslog-ng)
    UDP: raw bytes, one datagram = one log line.
    """
    msg = _rfc3164_header() + msg
    encoded = msg.encode("utf-8", errors="replace")

    if len(encoded) > SYSLOG_MAX_MSG_BYTES:
        marker  = b" [TRUNCATED]"
        budget  = SYSLOG_MAX_MSG_BYTES - len(marker)
        encoded = encoded[:budget] + marker
        log.warning(
            "syslog: message truncated to %d bytes (app=%s).",
            len(encoded), app_name,
        )

    if SYSLOG_TRANSPORT == "tcp":
        if SYSLOG_TCP_FRAMING == "newline":
            return encoded.rstrip(b"\r\n") + b"\n"
        # Octet-count framing per RFC 6587.
        return f"{len(encoded)} ".encode() + encoded
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

    try:
        _syslog_queue.put_nowait((msg, app_name))
    except queue.Full:
        log.warning(
            "syslog queue full (maxsize=%d); message dropped.",
            _SYSLOG_QUEUE_MAXSIZE,
        )
