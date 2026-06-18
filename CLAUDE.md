# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the poller
python cortex.py

# Run tests (all formats)
python test_comprehensive.py
python test_async_writes.py
python test_alerts_incidents.py

# Test with a specific output format
OUTPUT_FORMAT=cef  python test_comprehensive.py
OUTPUT_FORMAT=json python test_comprehensive.py

# Docker syslog receiver (for integration testing)
docker build -f Dockerfile.syslog -t cortex-syslog .
docker run -d --name cortex-syslog -p 5514:5514/tcp -v /tmp/cortex-syslog:/logs cortex-syslog
```

## Architecture

**See `CODEBASE.md` for the authoritative detailed reference.** What follows is the minimum context needed to orient quickly.

The poller is a multi-threaded daemon. `cortex.py` starts **4 independent daemon threads** — one per data stream (alerts, incidents, mgmt audits, agent audits). Each thread runs its stream's poll function in an infinite loop, sleeping `POLL_INTERVAL_SECONDS` between cycles. A failing stream logs the exception and restarts on the next cycle; it does not kill the other threads.

### Layer Map

| Layer | Files | Role |
|---|---|---|
| Entry | `cortex.py` | Spawns 4 threads, joins them |
| Config | `config.py` | All env-var loading, single source of truth |
| Poll engine | `poller_base.py` | Shared: lookback, fetch, format, log, syslog, state |
| Stream pollers | `poller_alerts.py`, `poller_incidents.py`, `poller_mgmt_audit.py`, `poller_agent_audit.py` | Stream-specific wrappers around `poller_base` |
| API clients | `api_base.py` + `api_*.py` | Paginated HTTP fetch with retry/backoff |
| Formatters | `formatters.py`, `leef.py` | LEEF 1.0, CEF 0, JSON, QRadar-DSM dispatch |
| Output | `logging_setup.py` | Async rotating file loggers (100 MB / daily) |
| Syslog | `syslog_handler.py` | RFC 5424 TCP (octet-count or newline) / UDP sender |
| State | `state.py` | Atomic read/write of `cortex_state.json` |

### Key Invariants (non-obvious, easy to break)

1. **All Cortex XDR timestamps are epoch milliseconds** — `epoch_to_iso()` always divides by 1000. Never pass raw seconds.
2. **State only advances on full page-set success.** `fetch_all()` returns `None` on any page failure; `poll_stream` leaves state unchanged. A failed cycle re-fetches from the same `since_ts` next run.
3. **Format failures skip the record but do not advance the cursor.** A persistently bad record is re-fetched indefinitely until it either succeeds or is no longer the newest record.
4. **The API silently caps results at 9999 records.** The poller logs a WARNING but records beyond the cap are dropped. Reduce `LOOKBACK_DAYS` or `POLL_INTERVAL_SECONDS` if this occurs.
5. **Incidents use `modification_time` as the cursor**, not `creation_time`. Updated incidents are re-emitted on subsequent polls — this is intentional.
6. **Audit endpoints use different field names for filter vs response.** The API filter field is `timestamp`; the response body uses `AUDIT_INSERT_TIME` (mgmt) or `TIMESTAMP` (agent).

## Configuration

All configuration is via `.env` (copy `.env.example`). Required: `api_key`, `api_key_id`, `url`. Key optional vars: `OUTPUT_FORMAT` (`leef`/`cef`/`json`/`qradar`), `ENABLE_SYSLOG`, `SYSLOG_TCP_FRAMING` (`octet` or `newline`), `SYSLOG_HOSTNAME` (when set, prepends an RFC 3164 header so QRadar uses it as the Log Source Identifier instead of the packet source IP), `LOOKBACK_HOURS`/`LOOKBACK_DAYS`.

## Deployment

```bash
# Deployment Commands
cp cortex.py /opt/cortex_xdr_poller/cortex.py
cp config.py /opt/cortex_xdr_poller/config.py
# etc. — use relative paths, one command per file, no env variables
```

## Testing

- Always run the full test suite after multi-file refactors and report pass/fail counts before declaring work complete.
- `test_comprehensive.py` covers 37 checks including auth, pagination, state, threads, log integrity, and syslog delivery.
- `test_async_writes.py` covers 22 checks benchmarking the async pipeline.
- Tests are format-aware: set `OUTPUT_FORMAT=` before running to exercise a specific format.

## Task Interpretation

When adding, saving, or fixing a feature, verify the current state first (does it exist? is it broken?) before acting.

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `python3 -c "from graphify.watch import _rebuild_code; from pathlib import Path; _rebuild_code(Path('.'))"` to keep the graph current
