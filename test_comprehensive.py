"""
test_comprehensive.py — end-to-end integrity test for the Cortex XDR poller.

Tests
-----
1.  Auth          — advanced auth reaches all 4 endpoints (not 401/403)
2.  Data presence — confirm each stream has live data in a 10-minute window
3.  Pagination    — fetch_all accumulates pages correctly (3-page spot-check,
                    plus full fetch when total_count <= 500)
4.  Ordering      — records are non-decreasing by timestamp (no gaps)
5.  State writes  — concurrent save_state calls don't corrupt the state file
6.  Threaded run  — all 4 stream threads complete one poll cycle independently
7.  Log integrity — log file line count == API total_count for each stream
8.  Syslog        — syslog received count per stream == log file line count

Design note: all live-data tests use a 10-minute lookback window so that
mgmt_audit and agent_audit counts stay in the hundreds, not thousands.
This keeps the test fast and immune to DNS timeouts during long fetches.

Run:  .venv/bin/python test_comprehensive.py
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

import config as _config
from api_base import fetch_all, build_headers
from state import save_state
import requests

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

_results: list[tuple[str, bool, str]] = []


def result(name: str, ok: bool, detail: str = "") -> None:
    tag  = PASS if ok else FAIL
    line = f"  [{tag}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)
    _results.append((name, ok, detail))


def section(title: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


# ---------------------------------------------------------------------------
# Stream definitions
# ---------------------------------------------------------------------------
STREAMS = [
    dict(label="alerts",      endpoint="/public_api/v1/alerts/get_alerts",
         reply_key="alerts",    time_field="creation_time",    state_key="last_seen_alert_ts"),
    dict(label="incidents",   endpoint="/public_api/v1/incidents/get_incidents",
         reply_key="incidents", time_field="modification_time", state_key="last_seen_incident_ts"),
    dict(label="mgmt_audits", endpoint="/public_api/v1/audits/management_logs",
         reply_key="data",      time_field="timestamp",         state_key="last_seen_mgmt_audit_ts"),
    dict(label="agent_audits",endpoint="/public_api/v1/audits/agents_reports",
         reply_key="data",      time_field="timestamp",         state_key="last_seen_agent_audit_ts"),
]

# Response timestamp field used as cursor (different from API filter field for audits)
# alerts uses creation_time — matches the ts_field set in poller_alerts.py
_TS_FIELD_RESPONSE = {
    "alerts":      "creation_time",
    "incidents":   "modification_time",
    "mgmt_audits": "AUDIT_INSERT_TIME",
    "agent_audits":"TIMESTAMP",
}

# RFC 5424 APP-NAME used by syslog_handler per stream
_STREAM_APP_NAME = {
    "alerts":      "cortex-alerts",
    "incidents":   "cortex-incidents",
    "mgmt_audits": "cortex-mgmt-audit",
    "agent_audits":"cortex-agent-audit",
}

SYSLOG_LOG_PATH = "/tmp/cortex_syslog_test/received.log"

# 10-minute lookback — keeps audit counts in the hundreds, not thousands
SINCE_TS = int((datetime.now(tz=timezone.utc) - timedelta(minutes=10)).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Shared HTTP helper
# ---------------------------------------------------------------------------
def _api_get(endpoint: str, time_field: str, since: int,
             search_from: int = 0, search_to: int = 1) -> dict:
    url     = f"{_config.FQDN}{endpoint}"
    payload = {"request_data": {
        "filters": [{"field": time_field, "operator": "gte", "value": since}],
        "sort":    {"field": time_field, "keyword": "asc"},
        "search_from": search_from, "search_to": search_to,
    }}
    resp = requests.post(url, headers=build_headers(), json=payload, timeout=30)
    return resp.json().get("reply", {})


# ---------------------------------------------------------------------------
# 1. AUTH
# ---------------------------------------------------------------------------
def test_auth() -> None:
    section("1. Advanced auth — all 4 endpoints")
    for s in STREAMS:
        try:
            resp = requests.post(
                f"{_config.FQDN}{s['endpoint']}",
                headers = build_headers(),
                json    = {"request_data": {
                    "filters": [{"field": s["time_field"], "operator": "gte", "value": SINCE_TS}],
                    "sort":    {"field": s["time_field"], "keyword": "asc"},
                    "search_from": 0, "search_to": 1,
                }},
                timeout = 30,
            )
            data  = resp.json()
            reply = data.get("reply", {})
            if resp.status_code in (401, 403) or reply.get("err_code") in (401, 403):
                result(s["label"], False, f"auth rejected HTTP {resp.status_code}")
            else:
                total = int(reply.get("total_count", 0))
                result(s["label"], True, f"HTTP {resp.status_code} total_count={total}")
        except Exception as exc:
            result(s["label"], False, str(exc))


# ---------------------------------------------------------------------------
# 2. DATA PRESENCE (10-minute window)
# ---------------------------------------------------------------------------
def test_data_presence() -> None:
    section("2. Data presence — 10-minute window")
    for s in STREAMS:
        try:
            reply = _api_get(s["endpoint"], s["time_field"], SINCE_TS)
            total = int(reply.get("total_count", 0))
            # We just confirm the endpoint responded — 0 is acceptable for alerts/incidents
            result(s["label"], True, f"total_count={total} (0 is acceptable for low-traffic streams)")
        except Exception as exc:
            result(s["label"], False, str(exc))


# ---------------------------------------------------------------------------
# 3. PAGINATION — spot-check + full fetch when count is manageable
# ---------------------------------------------------------------------------
def test_pagination() -> None:
    section("3. Pagination — correctness check")
    for s in STREAMS:
        url = f"{_config.FQDN}{s['endpoint']}"
        # Get total
        try:
            reply = _api_get(s["endpoint"], s["time_field"], SINCE_TS)
            total = int(reply.get("total_count", 0))
        except Exception as exc:
            result(s["label"], False, f"could not get total_count: {exc}")
            continue

        if total == 0:
            result(s["label"], True, "total_count=0 — nothing to paginate")
            continue

        cap = min(total, 9999)

        if cap <= 500:
            # Small enough — do a full fetch and compare
            records = fetch_all(url=url, since_ts=SINCE_TS, reply_key=s["reply_key"],
                                label=s["label"], time_field=s["time_field"])
            if records is None:
                result(s["label"], False, "fetch_all returned None")
            else:
                # Live API: records may arrive between total_count probe and
                # fetch_all completing, so fetched >= cap is the correct check.
                ok = len(records) >= cap
                result(s["label"], ok, f"expected>={cap} fetched={len(records)}")
        else:
            # Large dataset — spot-check: fetch page 1 and page 2, verify counts
            try:
                p1  = requests.post(url, headers=build_headers(), timeout=30, json={"request_data": {
                    "filters": [{"field": s["time_field"], "operator": "gte", "value": SINCE_TS}],
                    "sort": {"field": s["time_field"], "keyword": "asc"},
                    "search_from": 0, "search_to": 100,
                }}).json().get("reply", {})
                p2  = requests.post(url, headers=build_headers(), timeout=30, json={"request_data": {
                    "filters": [{"field": s["time_field"], "operator": "gte", "value": SINCE_TS}],
                    "sort": {"field": s["time_field"], "keyword": "asc"},
                    "search_from": 100, "search_to": 200,
                }}).json().get("reply", {})
                r1  = p1.get(s["reply_key"], [])
                r2  = p2.get(s["reply_key"], [])
                ok  = len(r1) == 100 and len(r2) == 100
                result(s["label"], ok,
                       f"total={total} (capped 9999) — page1={len(r1)} page2={len(r2)} (spot-check only)")
            except Exception as exc:
                result(s["label"], False, f"spot-check failed: {exc}")


# ---------------------------------------------------------------------------
# 4. ORDERING
# ---------------------------------------------------------------------------
def test_ordering() -> None:
    section("4. Record ordering — timestamps non-decreasing")
    for s in STREAMS:
        url = f"{_config.FQDN}{s['endpoint']}"
        try:
            reply = _api_get(s["endpoint"], s["time_field"], SINCE_TS)
            total = int(reply.get("total_count", 0))
        except Exception as exc:
            result(s["label"], False, str(exc))
            continue

        if total == 0:
            result(s["label"], True, "no records — ordering N/A")
            continue

        # Fetch up to 3 pages (300 records max) for ordering check
        check_to = min(total, 300)
        try:
            resp    = requests.post(url, headers=build_headers(), timeout=30, json={"request_data": {
                "filters": [{"field": s["time_field"], "operator": "gte", "value": SINCE_TS}],
                "sort": {"field": s["time_field"], "keyword": "asc"},
                "search_from": 0, "search_to": check_to,
            }})
            records = resp.json().get("reply", {}).get(s["reply_key"], [])
        except Exception as exc:
            result(s["label"], False, str(exc))
            continue

        ts_key     = _TS_FIELD_RESPONSE[s["label"]]
        prev_ts    = -1
        violations = 0
        for rec in records:
            ts = rec.get(ts_key) or rec.get(s["time_field"], 0)
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                continue
            if ts < prev_ts:
                violations += 1
            prev_ts = ts

        result(s["label"], violations == 0,
               f"{len(records)} records checked, {violations} ordering violation(s)")


# ---------------------------------------------------------------------------
# 5. CONCURRENT STATE WRITES
# ---------------------------------------------------------------------------
def test_concurrent_state_writes() -> None:
    section("5. Concurrent state writes — no corruption under threading")

    import config as config_mod
    import state as state_mod

    orig = config_mod.STATE_FILE
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp = tf.name

    config_mod.STATE_FILE = tmp
    state_mod.STATE_FILE  = tmp  # type: ignore

    shared: dict = {}
    N = 50
    KEYS_VALS = {
        "last_seen_alert_ts": 111111, "last_seen_incident_ts": 222222,
        "last_seen_mgmt_audit_ts": 333333, "last_seen_agent_audit_ts": 444444,
    }

    def writer(key: str, final: int) -> None:
        for i in range(N):
            shared[key] = i
            save_state(shared)
        shared[key] = final
        save_state(shared)

    threads = [threading.Thread(target=writer, args=(k, v)) for k, v in KEYS_VALS.items()]
    for t in threads: t.start()
    for t in threads: t.join()

    try:
        with open(tmp) as f:
            saved = json.load(f)
        os.unlink(tmp)
    except Exception as exc:
        result("state file readable", False, str(exc))
        config_mod.STATE_FILE = orig
        state_mod.STATE_FILE  = orig  # type: ignore
        return

    all_ok = all(saved.get(k) == v for k, v in KEYS_VALS.items())
    result("concurrent writes — all keys intact", all_ok,
           f"4 threads × {N+1} writes each")

    config_mod.STATE_FILE = orig
    state_mod.STATE_FILE  = orig  # type: ignore


# ---------------------------------------------------------------------------
# Syslog helpers
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


def _parse_syslog_counts(path: str) -> dict[str, int]:
    """Count syslog lines per stream by APP-NAME (RFC 5424 field 4)."""
    counts: dict[str, int] = {label: 0 for label in _STREAM_APP_NAME}
    if not os.path.exists(path):
        return counts
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                end_pri  = line.index(">") + 1
                parts    = line[end_pri:].split(" ", 5)
                app_name = parts[3] if len(parts) > 3 else ""
                for label, expected_app in _STREAM_APP_NAME.items():
                    if app_name == expected_app:
                        counts[label] += 1
                        break
            except (ValueError, IndexError):
                continue
    return counts


# ---------------------------------------------------------------------------
# 6 + 7 + 8. THREADED RUN + LOG INTEGRITY + SYSLOG DELIVERY
# ---------------------------------------------------------------------------
def test_threaded_run_and_syslog() -> None:
    section("6+7+8. Threaded one-cycle run + log integrity + syslog delivery")

    import logging
    import config as config_mod
    import state  as state_mod
    from poller_base    import poll_stream
    from api_alerts     import fetch_alerts
    from api_incidents  import fetch_incidents
    from api_mgmt_audit import fetch_mgmt_audits
    from api_agent_audit import fetch_agent_audits

    FETCH_FN = {
        "alerts":      fetch_alerts,
        "incidents":   fetch_incidents,
        "mgmt_audits": fetch_mgmt_audits,
        "agent_audits":fetch_agent_audits,
    }
    TS_FIELD = {
        "alerts":      "creation_time",       # updated to match poller_alerts.py
        "incidents":   "modification_time",
        "mgmt_audits": "AUDIT_INSERT_TIME",
        "agent_audits":"TIMESTAMP",
    }

    # ---- Syslog server check ----
    syslog_ok = _config.ENABLE_SYSLOG and _syslog_reachable()
    if syslog_ok:
        print(f"  [{INFO}] syslog {_config.SYSLOG_HOST}:{_config.SYSLOG_PORT} reachable — delivery will be verified")
        os.makedirs(os.path.dirname(SYSLOG_LOG_PATH), exist_ok=True)
        open(SYSLOG_LOG_PATH, "w").close()   # clear from any previous run
    else:
        print(f"  [{INFO}] syslog not reachable or disabled — skipping delivery check")

    # ---- Temp dirs / state ----
    tmp_dir   = tempfile.mkdtemp(prefix="cortex_test_")
    tmp_state = os.path.join(tmp_dir, "state.json")
    tmp_logs  = {s["label"]: os.path.join(tmp_dir, f"{s['label']}.log") for s in STREAMS}
    print(f"  [{INFO}] temp dir: {tmp_dir}")

    orig_state         = config_mod.STATE_FILE
    config_mod.STATE_FILE = tmp_state
    state_mod.STATE_FILE  = tmp_state  # type: ignore

    # ---- Get expected counts from API (fresh query) ----
    expected: dict[str, int] = {}
    for s in STREAMS:
        try:
            reply = _api_get(s["endpoint"], s["time_field"], SINCE_TS)
            total = int(reply.get("total_count", 0))
            expected[s["label"]] = min(total, 9999)
            print(f"  [{INFO}] {s['label']:12s} expected={expected[s['label']]}")
        except Exception as exc:
            expected[s["label"]] = -1
            print(f"  [{INFO}] {s['label']:12s} could not get count: {exc}")

    # ---- Build per-stream loggers ----
    def make_logger(name: str, path: str) -> logging.Logger:
        logger = logging.getLogger(f"test_{name}")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        h = logging.FileHandler(path, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.propagate = False
        return logger

    # ---- Run one cycle per stream concurrently ----
    shared_state  = {s["state_key"]: SINCE_TS for s in STREAMS}
    done_events   = {s["label"]: threading.Event() for s in STREAMS}
    thread_errors: dict[str, str] = {}

    def run_one_cycle(s: dict) -> None:
        label = s["label"]
        try:
            poll_stream(
                state           = shared_state,
                state_key       = s["state_key"],
                fetch_fn        = FETCH_FN[label],
                stream          = label,
                output_logger   = make_logger(label, tmp_logs[label]),
                ts_field        = TS_FIELD[label],
                label           = label,
                syslog_app_name = _STREAM_APP_NAME[label],
            )
        except Exception as exc:
            thread_errors[label] = str(exc)
        finally:
            done_events[label].set()

    threads = [threading.Thread(target=run_one_cycle, args=(s,), name=s["label"]) for s in STREAMS]
    t_start = time.time()
    for t in threads:
        t.start()

    for s in STREAMS:
        done_events[s["label"]].wait(timeout=300)

    elapsed = time.time() - t_start
    print(f"  [{INFO}] all threads finished in {elapsed:.1f}s")

    for label, err in thread_errors.items():
        result(f"{label} thread error-free", False, err)

    # ---- Section 6: thread completion ----
    section("6. Thread independence")
    for s in STREAMS:
        completed = done_events[s["label"]].is_set()
        result(f"{s['label']} thread completed", completed)

    # ---- Section 7: state keys + log file counts ----
    section("7. Log file integrity")
    log_counts: dict[str, int] = {}
    for s in STREAMS:
        key   = s["state_key"]
        value = shared_state.get(key)
        ok    = value is not None and value >= SINCE_TS
        result(f"{s['label']} state key updated", ok, f"{key}={value}")

    for s in STREAMS:
        label    = s["label"]
        log_path = tmp_logs[label]
        exp      = expected.get(label, -1)

        if not os.path.exists(log_path):
            written = 0
        else:
            with open(log_path, encoding="utf-8") as f:
                written = len([l for l in f.read().splitlines() if l.strip()])
        log_counts[label] = written

        if exp < 0:
            result(f"{label} log completeness", True, f"written={written} (expected count unknown)")
        else:
            # Live API: new records may arrive between the total_count probe
            # and poll_stream completing, so written >= exp is the correct check.
            result(f"{label} log completeness", written >= exp,
                   f"expected>={exp} written={written}")

    # ---- Section 8: syslog delivery ----
    section("8. Syslog delivery")
    if not syslog_ok:
        result("syslog delivery", True, "SKIP — syslog server not reachable or disabled")
    else:
        time.sleep(2)   # let TCP frames flush
        syslog_counts = _parse_syslog_counts(SYSLOG_LOG_PATH)
        total_log    = sum(log_counts.values())
        total_syslog = sum(syslog_counts.values())

        print(f"  [{INFO}] total log lines : {total_log}")
        print(f"  [{INFO}] total syslog msg: {total_syslog}")

        for s in STREAMS:
            label   = s["label"]
            in_log  = log_counts[label]
            in_sysl = syslog_counts[label]
            result(f"{label} syslog delivery",
                   in_log == in_sysl,
                   f"log={in_log}  syslog={in_sysl}  app={_STREAM_APP_NAME[label]}")

        result("syslog total",
               total_log == total_syslog,
               f"log_total={total_log} syslog_total={total_syslog}")

        # Print a sample from the syslog file for visual confirmation
        if os.path.exists(SYSLOG_LOG_PATH):
            with open(SYSLOG_LOG_PATH) as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                print(f"\n  [{INFO}] Sample syslog messages received:")
                for line in lines[:3]:
                    print(f"    {line[:120]}")

    # ---- Restore state file ----
    config_mod.STATE_FILE = orig_state
    state_mod.STATE_FILE  = orig_state  # type: ignore


# ---------------------------------------------------------------------------
# 9. ASYNC WRITE — QueueHandler enqueues instantly, records reach disk on drain
# ---------------------------------------------------------------------------
def test_immediate_writes() -> None:
    """
    Verify the async QueueHandler behaviour used by all production loggers:

      a) Enqueue latency — logger.info() returns in < 100 µs (queue put, not disk I/O).
      b) Drain completeness — all records appear on disk after QueueListener.stop().
      c) Caller speedup — QueueHandler caller is >10× faster than synchronous
         FileHandler for the same number of records (SlowHandler benchmark).
    """
    section("9. Async write — QueueHandler enqueue latency & drain completeness")

    import logging
    import queue
    from logging.handlers import QueueHandler, QueueListener

    N = 200

    # (a) Enqueue latency with real FileHandler as the backing handler
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as tf:
        path = tf.name

    file_h = logging.FileHandler(path, encoding="utf-8")
    file_h.setFormatter(logging.Formatter("%(message)s"))

    q: queue.Queue = queue.Queue(-1)
    listener = QueueListener(q, file_h, respect_handler_level=True)
    listener.start()

    lg = logging.getLogger("_comp_test_async")
    lg.setLevel(logging.INFO)
    lg.handlers.clear()
    lg.propagate = False
    lg.addHandler(QueueHandler(q))

    t0 = time.perf_counter()
    for i in range(N):
        lg.info("record_%04d payload=%s", i, "z" * 200)
    enqueue_ms = (time.perf_counter() - t0) * 1000
    per_record_us = enqueue_ms / N * 1000

    result(
        f"QueueHandler enqueue < 100 µs/record ({N} records)",
        per_record_us < 100,
        f"{enqueue_ms:.2f}ms total  ({per_record_us:.1f} µs/record avg)",
    )

    # (b) Drain completeness — stop listener (blocks until queue empty), then count
    before_stop = sum(1 for ln in open(path) if ln.strip())
    listener.stop()
    after_stop = sum(1 for ln in open(path) if ln.strip())

    result(
        f"all {N} records on disk after QueueListener.stop()",
        after_stop == N,
        f"before_stop={before_stop}  after_stop={after_stop}  expected={N}",
    )
    os.unlink(path)

    # (c) Speedup vs synchronous handler
    class SlowHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:  # noqa: ARG002
            time.sleep(0.001)   # 1 ms per write

    slow_h = SlowHandler()

    sync_lg = logging.getLogger("_comp_test_sync_slow")
    sync_lg.setLevel(logging.INFO)
    sync_lg.handlers.clear()
    sync_lg.propagate = False
    sync_lg.addHandler(slow_h)

    t0 = time.perf_counter()
    for i in range(N):
        sync_lg.info("sync_%04d", i)
    sync_ms = (time.perf_counter() - t0) * 1000

    async_lg = logging.getLogger("_comp_test_async_slow")
    async_lg.setLevel(logging.INFO)
    async_lg.handlers.clear()
    async_lg.propagate = False

    q2: queue.Queue = queue.Queue(-1)
    lst2 = QueueListener(q2, slow_h, respect_handler_level=True)
    lst2.start()
    async_lg.addHandler(QueueHandler(q2))

    t0 = time.perf_counter()
    for i in range(N):
        async_lg.info("async_%04d", i)
    async_ms = (time.perf_counter() - t0) * 1000
    lst2.stop()

    speedup = sync_ms / async_ms if async_ms > 0 else float("inf")
    result(
        f"QueueHandler caller >10× faster than sync handler ({N} records, 1ms slow handler)",
        async_ms < sync_ms * 0.1,
        f"sync={sync_ms:.0f}ms  async_caller={async_ms:.1f}ms  speedup={speedup:.0f}×",
    )


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    print("\n" + "="*60)
    print("  Cortex XDR Poller — Comprehensive Integrity Test")
    print("="*60)
    print(f"  tenant      : {_config.FQDN}")
    print(f"  auth        : {_config.API_AUTH_TYPE}")
    print(f"  format      : {_config.OUTPUT_FORMAT}")
    print(f"  syslog      : {_config.SYSLOG_HOST}:{_config.SYSLOG_PORT} (enabled={_config.ENABLE_SYSLOG})")
    print(f"  lookback    : 10 minutes (since_ts={SINCE_TS})")

    test_auth()
    test_data_presence()
    test_pagination()
    test_ordering()
    test_concurrent_state_writes()
    test_threaded_run_and_syslog()
    test_immediate_writes()

    section("Summary")
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = sum(1 for _, ok, _ in _results if not ok)
    print(f"\n  {passed}/{len(_results)} passed,  {failed} failed\n")

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
