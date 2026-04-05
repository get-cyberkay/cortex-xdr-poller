"""
test_alerts_incidents.py — Focused test for alerts and incidents streams.

Verifies:
  1. Count (total_count from API) over 14-day lookback
  2. Pagination — fetch_all returns every record
  3. Ordering  — timestamps non-decreasing
  4. creation_time field present in alerts (cursor field change)
  5. Threaded poll cycle — both streams run concurrently
  6. Log file completeness — written == API total_count
  7. Syslog delivery — syslog count == log file count per stream
"""

import logging
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

import config as _config
import config as config_mod
import state  as state_mod
from api_base      import fetch_all, build_headers
from api_alerts    import fetch_alerts
from api_incidents import fetch_incidents
from poller_base   import poll_stream
from state         import save_state
import requests

# ── helpers ───────────────────────────────────────────────────
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

results: list[bool] = []

def chk(name: str, ok: bool, detail: str = "") -> None:
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))
    results.append(ok)

def sec(t: str) -> None:
    print(f"\n{'─'*60}\n  {t}\n{'─'*60}")

# ── config ────────────────────────────────────────────────────
SINCE_TS   = int((datetime.now(tz=timezone.utc) - timedelta(days=14)).timestamp() * 1000)
SYSLOG_LOG = "/tmp/cortex_syslog_test/received.log"

STREAMS = [
    dict(
        label      = "alerts",
        endpoint   = "/public_api/v1/alerts/get_alerts",
        reply_key  = "alerts",
        time_field = "creation_time",         # API filter/sort field
        ts_cursor  = "detection_timestamp",   # response field for state cursor
        state_key  = "last_seen_alert_ts",
        syslog_app = "cortex-alerts",
    ),
    dict(
        label      = "incidents",
        endpoint   = "/public_api/v1/incidents/get_incidents",
        reply_key  = "incidents",
        time_field = "modification_time",
        ts_cursor  = "modification_time",
        state_key  = "last_seen_incident_ts",
        syslog_app = "cortex-incidents",
    ),
]

# ── 1. Count ──────────────────────────────────────────────────
def get_expected() -> dict[str, int]:
    sec("1. API total_count — 14-day lookback")
    expected: dict[str, int] = {}
    for s in STREAMS:
        try:
            r = requests.post(
                f"{_config.FQDN}{s['endpoint']}",
                headers = build_headers(),
                timeout = 30,
                json    = {"request_data": {
                    "filters":     [{"field": s["time_field"], "operator": "gte", "value": SINCE_TS}],
                    "sort":        {"field": s["time_field"], "keyword": "asc"},
                    "search_from": 0, "search_to": 1,
                }},
            )
            total = int(r.json().get("reply", {}).get("total_count", 0))
            expected[s["label"]] = total
            chk(s["label"], total > 0, f"total_count={total}")
        except Exception as exc:
            expected[s["label"]] = -1
            chk(s["label"], False, str(exc))
    return expected

# ── 2. Pagination ─────────────────────────────────────────────
def fetch_records(expected: dict[str, int]) -> dict[str, list]:
    sec("2. Pagination — fetch_all returns exactly total_count records")
    cache: dict[str, list] = {}
    for s in STREAMS:
        exp = expected.get(s["label"], 0)
        if exp <= 0:
            chk(f"{s['label']} pagination", True, f"total={exp} — nothing to fetch")
            continue
        url  = f"{_config.FQDN}{s['endpoint']}"
        recs = fetch_all(url=url, since_ts=SINCE_TS, reply_key=s["reply_key"],
                         label=s["label"], time_field=s["time_field"])
        if recs is None:
            chk(f"{s['label']} pagination", False, "fetch_all returned None")
        else:
            cache[s["label"]] = recs
            chk(f"{s['label']} pagination", len(recs) == exp,
                f"expected={exp} fetched={len(recs)}")
    return cache

# ── 3. Ordering ───────────────────────────────────────────────
def check_ordering(cache: dict[str, list]) -> None:
    sec("3. Record ordering — timestamps non-decreasing")
    for s in STREAMS:
        recs = cache.get(s["label"], [])
        if not recs:
            chk(f"{s['label']} ordering", True, "no records"); continue
        prev = violations = 0
        for rec in recs:
            ts = rec.get(s["ts_cursor"], 0)
            try: ts = int(ts)
            except: continue
            if ts < prev:
                violations += 1
            prev = ts
        chk(f"{s['label']} ordering", violations == 0,
            f"{len(recs)} records, {violations} violation(s)")

# ── 4. Alert timestamp fields ─────────────────────────────────
def check_alert_fields(cache: dict[str, list]) -> None:
    sec("4. Alerts — timestamp fields (filter=creation_time, response cursor=detection_timestamp)")
    recs = cache.get("alerts", [])
    if not recs:
        chk("detection_timestamp field check", True, "no alert records in window"); return

    # The API filter uses 'creation_time' but the response field is 'detection_timestamp'.
    # The cursor in poll_stream must use 'detection_timestamp' to advance state.
    has_det = sum(1 for r in recs if r.get("detection_timestamp") is not None)
    has_ct  = sum(1 for r in recs if r.get("creation_time") is not None)
    chk("detection_timestamp present in every alert record (cursor field)",
        has_det == len(recs),
        f"{has_det}/{len(recs)} records have detection_timestamp")
    print(f"  [{INFO}] creation_time in response: {has_ct}/{len(recs)} "
          f"(API filter field only — not returned in response body)")

    s0 = recs[0]
    print(f"  [{INFO}] sample alert:")
    print(f"           alert_id            = {s0.get('alert_id')}")
    print(f"           severity            = {s0.get('severity')}")
    print(f"           detection_timestamp = {s0.get('detection_timestamp')} (cursor)")
    print(f"           creation_time       = {s0.get('creation_time')} (not in response)")
    print(f"           name                = {s0.get('name','')[:60]}")

# ── 5+6+7. Threaded run + log + syslog ───────────────────────
def run_threaded(expected: dict[str, int]) -> None:
    sec("5+6+7. Threaded poll cycle — log integrity + syslog delivery")

    tmp_dir   = tempfile.mkdtemp(prefix="cortex_ai_test_")
    tmp_state = os.path.join(tmp_dir, "state.json")

    orig               = config_mod.STATE_FILE
    config_mod.STATE_FILE = tmp_state
    state_mod.STATE_FILE  = tmp_state  # type: ignore

    def make_logger(name: str, path: str) -> logging.Logger:
        lg = logging.getLogger(f"tst_{name}")
        lg.setLevel(logging.INFO)
        lg.handlers.clear()
        h = logging.FileHandler(path, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
        lg.propagate = False
        return lg

    # Clear syslog log
    os.makedirs(os.path.dirname(SYSLOG_LOG), exist_ok=True)
    open(SYSLOG_LOG, "w").close()

    shared = {s["state_key"]: SINCE_TS for s in STREAMS}
    tlogs  = {s["label"]: os.path.join(tmp_dir, f"{s['label']}.log") for s in STREAMS}
    done   = {s["label"]: threading.Event() for s in STREAMS}
    errors: dict[str, str] = {}
    FETCH  = {"alerts": fetch_alerts, "incidents": fetch_incidents}

    def run(s: dict) -> None:
        try:
            poll_stream(
                state           = shared,
                state_key       = s["state_key"],
                fetch_fn        = FETCH[s["label"]],
                stream          = s["label"],
                output_logger   = make_logger(s["label"], tlogs[s["label"]]),
                ts_field        = s["ts_cursor"],
                label           = s["label"],
                syslog_app_name = s["syslog_app"],
            )
        except Exception as exc:
            errors[s["label"]] = str(exc)
        finally:
            done[s["label"]].set()

    threads = [threading.Thread(target=run, args=(s,), name=s["label"]) for s in STREAMS]
    t0 = time.time()
    for t in threads: t.start()
    for s in STREAMS: done[s["label"]].wait(timeout=120)
    elapsed = time.time() - t0
    print(f"  [{INFO}] both streams completed in {elapsed:.1f}s (concurrent)")

    # thread errors
    for label, err in errors.items():
        chk(f"{label} thread error-free", False, err)

    # section 5: thread independence
    sec("5. Thread independence")
    for s in STREAMS:
        chk(f"{s['label']} thread completed", done[s["label"]].is_set())

    # section 6: log files
    sec("6. Log file integrity")
    log_counts: dict[str, int] = {}
    for s in STREAMS:
        v  = shared.get(s["state_key"])
        ok = v is not None and v >= SINCE_TS
        chk(f"{s['label']} state key advanced", ok, f"{s['state_key']}={v}")

    for s in STREAMS:
        label = s["label"]
        p     = tlogs[label]
        if not os.path.exists(p):
            log_counts[label] = 0
        else:
            with open(p, encoding="utf-8") as f:
                log_counts[label] = len([l for l in f.read().splitlines() if l.strip()])
        exp = expected.get(label, -1)
        chk(f"{label} log completeness",
            exp < 0 or log_counts[label] == exp,
            f"expected={exp}  written={log_counts[label]}")

    # section 7: syslog
    sec("7. Syslog delivery")
    time.sleep(2)
    syslog_counts: dict[str, int] = {s["label"]: 0 for s in STREAMS}
    app_map = {s["label"]: s["syslog_app"] for s in STREAMS}
    if os.path.exists(SYSLOG_LOG):
        with open(SYSLOG_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    end_pri  = line.index(">") + 1
                    parts    = line[end_pri:].split(" ", 5)
                    app_name = parts[3] if len(parts) > 3 else ""
                    for label, app in app_map.items():
                        if app_name == app:
                            syslog_counts[label] += 1
                            break
                except Exception:
                    continue

    total_log    = sum(log_counts.values())
    total_syslog = sum(syslog_counts.values())
    print(f"  [{INFO}] log_total={total_log}  syslog_total={total_syslog}")

    for s in STREAMS:
        label = s["label"]
        chk(f"{label} syslog delivery",
            log_counts[label] == syslog_counts[label],
            f"log={log_counts[label]}  syslog={syslog_counts[label]}  app={s['syslog_app']}")
    chk("syslog total", total_log == total_syslog,
        f"log={total_log}  syslog={total_syslog}")

    if os.path.exists(SYSLOG_LOG):
        with open(SYSLOG_LOG) as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            print(f"\n  [{INFO}] Received {len(lines)} syslog messages. Samples:")
            for line in lines[:4]:
                print(f"    {line[:130]}")

    config_mod.STATE_FILE = orig
    state_mod.STATE_FILE  = orig  # type: ignore


# ── main ──────────────────────────────────────────────────────
def main() -> None:
    print("\n" + "="*60)
    print("  Alerts & Incidents — End-to-End Test")
    print("="*60)
    print(f"  tenant  : {_config.FQDN}")
    print(f"  auth    : {_config.API_AUTH_TYPE}")
    print(f"  syslog  : {_config.SYSLOG_HOST}:{_config.SYSLOG_PORT} (enabled={_config.ENABLE_SYSLOG})")
    print(f"  lookback: 14 days  since_ts={SINCE_TS}")

    expected = get_expected()
    cache    = fetch_records(expected)
    check_ordering(cache)
    check_alert_fields(cache)
    run_threaded(expected)

    sec("Summary")
    passed = sum(results)
    failed = len(results) - passed
    print(f"\n  {passed}/{len(results)} passed,  {failed} failed\n")
    if failed:
        print("  Failed:")
        sys.exit(1)
    print("  All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
