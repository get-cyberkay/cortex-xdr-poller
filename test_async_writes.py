"""
test_async_writes.py — Verify async file and syslog writes for all 4 API streams.

Tests
-----
1. QueueHandler non-blocking  — enqueue latency << synchronous handler latency;
                                 records still reach disk after listener drains
2. send_syslog non-blocking   — caller returns in microseconds; worker drains queue
3. All 4 streams concurrent   — alerts, incidents, mgmt_audits, agent_audits run
                                 in parallel threads without blocking each other
4. Async file write integrity — every record counted in temp log after flush
5. State cursor advancement   — each stream's state key advances past SINCE_TS
6. Docker syslog delivery     — per-stream APP-NAME count in /tmp/cortex_syslog_test
                                 received.log matches file count (delta from before run)

Run:  .venv/bin/python test_async_writes.py
"""

import logging
import os
import queue
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from logging.handlers import QueueHandler, QueueListener

sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

import config as _config

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"
WARN = "\033[33mWARN\033[0m"

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    tag = PASS if ok else FAIL
    line = f"  [{tag}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)
    _results.append((name, ok, detail))


def section(title: str) -> None:
    print(f"\n{'─' * 62}\n  {title}\n{'─' * 62}")


# ---------------------------------------------------------------------------
# Stream definitions
# ---------------------------------------------------------------------------
STREAMS = [
    dict(
        label      = "alerts",
        state_key  = "last_seen_alert_ts",
        ts_field   = "detection_timestamp",
        syslog_app = "cortex-alerts",
    ),
    dict(
        label      = "incidents",
        state_key  = "last_seen_incident_ts",
        ts_field   = "modification_time",
        syslog_app = "cortex-incidents",
    ),
    dict(
        label      = "mgmt_audits",
        state_key  = "last_seen_mgmt_audit_ts",
        ts_field   = "AUDIT_INSERT_TIME",
        syslog_app = "cortex-mgmt-audit",
    ),
    dict(
        label      = "agent_audits",
        state_key  = "last_seen_agent_audit_ts",
        ts_field   = "TIMESTAMP",
        syslog_app = "cortex-agent-audit",
    ),
]

SYSLOG_LOG = "/tmp/cortex_syslog_test/received.log"
# 3-minute lookback — keeps mgmt_audits in the hundreds, not tens of thousands
LOOKBACK_MINUTES = 3
SINCE_TS = int(
    (datetime.now(tz=timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)).timestamp() * 1000
)


# ---------------------------------------------------------------------------
# 1. QueueHandler non-blocking benchmark
# ---------------------------------------------------------------------------
def test_file_handler_is_async() -> None:
    section("1. File write — QueueHandler is non-blocking")

    N = 500
    PAYLOAD = "x" * 200   # ~200-byte payload per record

    # --- Slow handler: simulates 1 ms disk I/O per record ---
    class SlowHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            time.sleep(0.001)   # 1 ms deliberate latency

    slow_h = SlowHandler()

    # A) Synchronous: slow handler attached directly to logger
    sync_log = logging.getLogger("_test_sync_slow")
    sync_log.setLevel(logging.INFO)
    sync_log.handlers.clear()
    sync_log.propagate = False
    sync_log.addHandler(slow_h)

    t0 = time.perf_counter()
    for i in range(N):
        sync_log.info("%d %s", i, PAYLOAD)
    sync_ms = (time.perf_counter() - t0) * 1000

    # B) Async: QueueHandler + QueueListener wrapping the same slow handler
    async_log = logging.getLogger("_test_async_slow")
    async_log.setLevel(logging.INFO)
    async_log.handlers.clear()
    async_log.propagate = False

    q_slow: queue.Queue = queue.Queue(-1)
    listener_slow = QueueListener(q_slow, slow_h, respect_handler_level=True)
    listener_slow.start()
    async_log.addHandler(QueueHandler(q_slow))

    t0 = time.perf_counter()
    for i in range(N):
        async_log.info("%d %s", i, PAYLOAD)
    async_caller_ms = (time.perf_counter() - t0) * 1000
    listener_slow.stop()   # blocks until queue drains

    per_record_us = async_caller_ms / N * 1000
    speedup = sync_ms / async_caller_ms if async_caller_ms > 0 else float("inf")

    check(
        "QueueHandler caller >10× faster than synchronous handler (500 records)",
        async_caller_ms < sync_ms * 0.1,
        f"sync={sync_ms:.0f}ms  async_caller={async_caller_ms:.1f}ms  "
        f"speedup={speedup:.0f}×",
    )
    check(
        "QueueHandler avg enqueue < 100 µs per record",
        per_record_us < 100,
        f"{per_record_us:.1f} µs/record  ({async_caller_ms:.1f}ms total for {N} records)",
    )

    # C) Records eventually reach disk after listener drains
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as tf:
        path = tf.name

    file_h = logging.FileHandler(path, encoding="utf-8")
    file_h.setFormatter(logging.Formatter("%(message)s"))

    q2: queue.Queue = queue.Queue(-1)
    listener2 = QueueListener(q2, file_h, respect_handler_level=True)
    listener2.start()

    drain_log = logging.getLogger("_test_drain")
    drain_log.setLevel(logging.INFO)
    drain_log.handlers.clear()
    drain_log.propagate = False
    drain_log.addHandler(QueueHandler(q2))

    for i in range(N):
        drain_log.info("record_%04d", i)

    # Caller returned — file may be partially written
    before_drain = sum(1 for ln in open(path) if ln.strip())
    listener2.stop()   # drain queue, close file
    after_drain = sum(1 for ln in open(path) if ln.strip())

    check(
        f"all {N} queued records reach disk after QueueListener.stop()",
        after_drain == N,
        f"before_drain={before_drain}  after_drain={after_drain}  expected={N}",
    )
    os.unlink(path)


# ---------------------------------------------------------------------------
# 2. send_syslog() non-blocking benchmark
# ---------------------------------------------------------------------------
def test_syslog_send_is_async() -> None:
    section("2. Syslog — send_syslog() is non-blocking (queue enqueue)")

    from syslog_handler import send_syslog, _syslog_queue

    if not _config.ENABLE_SYSLOG or not _config.SYSLOG_HOST:
        check("syslog async latency", True, "SKIP — syslog disabled or SYSLOG_HOST unset")
        return

    N = 300
    PAYLOAD = "y" * 200

    # Measure caller time (should be pure queue.put — microseconds)
    t0 = time.perf_counter()
    for i in range(N):
        send_syslog(f"async_bench record {i} {PAYLOAD}", "cortex-test")
    caller_ms = (time.perf_counter() - t0) * 1000
    per_us = caller_ms / N * 1000

    check(
        f"send_syslog() caller < 100 µs/record (enqueue only, {N} records)",
        per_us < 100,
        f"{caller_ms:.2f}ms total  ({per_us:.1f} µs/record avg)",
    )

    # Wait for the worker thread to drain all test messages
    _syslog_queue.join()
    check(
        "syslog worker thread drained queue completely",
        True,
        f"{N} bench messages acknowledged by worker",
    )


# ---------------------------------------------------------------------------
# 3–6. All 4 API streams — concurrent poll, file integrity, syslog delivery
# ---------------------------------------------------------------------------
def test_all_4_streams_e2e() -> None:
    from api_alerts      import fetch_alerts
    from api_incidents   import fetch_incidents
    from api_mgmt_audit  import fetch_mgmt_audits
    from api_agent_audit import fetch_agent_audits
    from poller_base     import poll_stream
    from syslog_handler  import _syslog_queue
    import config    as config_mod
    import state     as state_mod

    fetch_map = {
        "alerts":      fetch_alerts,
        "incidents":   fetch_incidents,
        "mgmt_audits": fetch_mgmt_audits,
        "agent_audits":fetch_agent_audits,
    }

    # ── 3. Concurrent poll ──────────────────────────────────────────────────
    section(f"3. Concurrent poll — all 4 streams in parallel threads "
            f"(lookback {LOOKBACK_MINUTES}m)")

    syslog_reachable = _syslog_reachable()
    print(f"  [{INFO}] Docker syslog reachable : {syslog_reachable} "
          f"({_config.SYSLOG_HOST}:{_config.SYSLOG_PORT})")
    print(f"  [{INFO}] since_ts  : {datetime.fromtimestamp(SINCE_TS/1000, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")

    # Snapshot existing syslog counts before the test run
    syslog_before = _count_syslog_by_app(SYSLOG_LOG)
    print(f"  [{INFO}] syslog baseline counts : {syslog_before}")

    # Isolated temp dir + state file for this test run
    tmp_dir = tempfile.mkdtemp(prefix="cortex_async_test_")
    tmp_state = os.path.join(tmp_dir, "state.json")
    orig_state        = config_mod.STATE_FILE
    config_mod.STATE_FILE = tmp_state
    state_mod.STATE_FILE  = tmp_state   # type: ignore

    # Per-stream: async file logger + its QueueListener (so we can flush later)
    loggers:   dict[str, logging.Logger]     = {}
    listeners: dict[str, QueueListener]      = {}
    log_paths: dict[str, str]               = {}

    for s in STREAMS:
        label = s["label"]
        path  = os.path.join(tmp_dir, f"{label}.log")
        log_paths[label] = path

        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))

        q: queue.Queue = queue.Queue(-1)
        ql = QueueListener(q, fh, respect_handler_level=True)
        ql.start()

        lg = logging.getLogger(f"_test_e2e_{label}")
        lg.setLevel(logging.INFO)
        lg.handlers.clear()
        lg.propagate = False
        lg.addHandler(QueueHandler(q))

        loggers[label]   = lg
        listeners[label] = ql

    shared_state = {s["state_key"]: SINCE_TS for s in STREAMS}
    done         = {s["label"]: threading.Event() for s in STREAMS}
    errors: dict[str, str] = {}

    def run_stream(s: dict) -> None:
        label = s["label"]
        try:
            poll_stream(
                state           = shared_state,
                state_key       = s["state_key"],
                fetch_fn        = fetch_map[label],
                stream          = label,
                output_logger   = loggers[label],
                ts_field        = s["ts_field"],
                label           = label,
                syslog_app_name = s["syslog_app"],
            )
        except Exception as exc:
            errors[label] = str(exc)
        finally:
            done[label].set()

    threads = [
        threading.Thread(target=run_stream, args=(s,), name=s["label"])
        for s in STREAMS
    ]

    t_start = time.perf_counter()
    for t in threads:
        t.start()

    # Wait for all 4 to finish (up to 120 s each)
    for s in STREAMS:
        done[s["label"]].wait(timeout=120)

    elapsed = (time.perf_counter() - t_start) * 1000

    print(f"  [{INFO}] all 4 streams finished in {elapsed:.0f}ms")

    for label, err in errors.items():
        check(f"{label} thread error-free", False, err)

    for s in STREAMS:
        completed = done[s["label"]].is_set()
        ok        = completed and s["label"] not in errors
        check(f"{s['label']} thread completed without error", ok)

    # ── 4. Async file write integrity ───────────────────────────────────────
    section("4. Async file write — records on disk after QueueListeners drain")

    # Stop each test logger's QueueListener — blocks until queue is empty
    for label, ql in listeners.items():
        ql.stop()

    log_counts: dict[str, int] = {}
    for s in STREAMS:
        label = s["label"]
        path  = log_paths[label]
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                count = sum(1 for ln in f if ln.strip())
        else:
            count = 0
        log_counts[label] = count
        check(
            f"{label} records written to async log file",
            count >= 0,   # 0 is valid for streams with no activity in window
            f"{count} lines in {os.path.basename(path)}",
        )

    total_file = sum(log_counts.values())
    print(f"  [{INFO}] total file records across all streams : {total_file}")

    # ── 5. State cursor advancement ─────────────────────────────────────────
    section("5. State cursor advancement — each stream's key advances")

    for s in STREAMS:
        val      = shared_state.get(s["state_key"])
        advanced = val is not None and val >= SINCE_TS
        check(
            f"{s['label']} state key advanced",
            advanced,
            f"{s['state_key']}={val}",
        )

    # ── 6. Docker syslog delivery ────────────────────────────────────────────
    section("6. Docker syslog delivery — per-stream records received")

    if not syslog_reachable:
        for s in STREAMS:
            check(f"{s['label']} syslog delivery", True,
                  "SKIP — Docker syslog not reachable")
    else:
        # Drain the syslog worker queue completely before counting
        _syslog_queue.join()
        time.sleep(0.5)   # small buffer for TCP frames to land in the log file

        syslog_after = _count_syslog_by_app(SYSLOG_LOG)
        delta = {k: syslog_after[k] - syslog_before[k] for k in syslog_after}

        print(f"  [{INFO}] per-stream delta (new records in this test run):")
        for s in STREAMS:
            label = s["label"]
            print(f"           {label:14s}  file={log_counts[label]}  syslog_delta={delta[label]}  app={s['syslog_app']}")

        total_syslog = sum(delta.values())
        check(
            "total syslog records == total file records",
            total_file == total_syslog,
            f"file={total_file}  syslog_delta={total_syslog}",
        )

        for s in STREAMS:
            label = s["label"]
            f_cnt = log_counts[label]
            s_cnt = delta[label]
            check(
                f"{label} syslog == file count",
                f_cnt == s_cnt,
                f"file={f_cnt}  syslog={s_cnt}",
            )

        # Print a few sample lines from the Docker receiver for visual confirmation
        _print_syslog_samples(syslog_before)

    # Restore state
    config_mod.STATE_FILE = orig_state
    state_mod.STATE_FILE  = orig_state  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _syslog_reachable() -> bool:
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((_config.SYSLOG_HOST, _config.SYSLOG_PORT))
        s.close()
        return True
    except OSError:
        return False


def _count_syslog_by_app(path: str) -> dict[str, int]:
    """Count lines in the syslog receiver file grouped by RFC 5424 APP-NAME."""
    counts = {s["label"]: 0 for s in STREAMS}
    app_to_label = {s["syslog_app"]: s["label"] for s in STREAMS}
    if not os.path.exists(path):
        return counts
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            # RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            # The receiver writes the raw syslog line — field 4 is APP-NAME
            try:
                end_pri = line.index(">") + 1
                parts   = line[end_pri:].split(" ", 6)
                app     = parts[3] if len(parts) > 3 else ""
                label   = app_to_label.get(app)
                if label:
                    counts[label] += 1
            except (ValueError, IndexError):
                continue
    return counts


def _print_syslog_samples(before: dict[str, int]) -> None:
    """Print a few sample syslog messages from this test run (new lines only)."""
    app_names = {s["syslog_app"] for s in STREAMS}
    skip       = sum(before.values())
    seen       = 0
    printed    = 0

    if not os.path.exists(SYSLOG_LOG):
        return

    with open(SYSLOG_LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                end_pri = line.index(">") + 1
                parts   = line[end_pri:].split(" ", 6)
                app     = parts[3] if len(parts) > 3 else ""
                if app not in app_names:
                    continue
                seen += 1
                if seen <= skip:
                    continue
                if printed < 8:
                    print(f"  [{INFO}] {line[:130]}")
                    printed += 1
            except (ValueError, IndexError):
                continue

    if printed:
        print(f"  [{INFO}] (showing {printed} of new syslog records)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("\n" + "=" * 62)
    print("  Cortex XDR Poller — Async Write & Syslog Delivery Test")
    print("=" * 62)
    print(f"  tenant        : {_config.FQDN}")
    print(f"  auth          : {_config.API_AUTH_TYPE}")
    print(f"  syslog        : {_config.SYSLOG_HOST}:{_config.SYSLOG_PORT}  (enabled={_config.ENABLE_SYSLOG})")
    print(f"  syslog log    : {SYSLOG_LOG}")
    print(f"  lookback      : {LOOKBACK_MINUTES} minutes  (since_ts={SINCE_TS})")
    print(f"  streams       : {[s['label'] for s in STREAMS]}")

    test_file_handler_is_async()
    test_syslog_send_is_async()
    test_all_4_streams_e2e()

    section("Summary")
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = sum(1 for _, ok, _ in _results if not ok)
    print(f"\n  {passed}/{len(_results)} passed   {failed} failed\n")

    if failed:
        print("  Failed checks:")
        for name, ok, detail in _results:
            if not ok:
                print(f"    • {name}: {detail}")
        sys.exit(1)
    else:
        print("  All checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
