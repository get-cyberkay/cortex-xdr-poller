# Cortex XDR Poller

Polls the Cortex XDR REST API for **alerts**, **incidents**, **management audit logs**, and **agent audit reports**. Converts every record to LEEF 2.0, CEF 0, or JSON and delivers it to rotating log files and/or a syslog server — all via a fully asynchronous, non-blocking pipeline.

---

## Features

- **4 independent data streams** — alerts, incidents, management audits, agent audits, each in its own thread
- **Fully async I/O** — API fetch, file writes, and syslog sends each run in their own worker; no operation blocks another
- **3 output formats** — LEEF 2.0 (QRadar), CEF 0 (ArcSight / Splunk), JSON
- **RFC 5424 syslog** over TCP (octet-count framing, RFC 6587) or UDP
- **Rotating log files** — daily midnight UTC + 100 MB size cap, 30 files retained
- **Resumable state** — per-stream cursor persisted to `cortex_state.json`; state advances per page so a mid-fetch failure wastes nothing
- **Advanced auth** — HMAC-SHA256 (nonce + timestamp) or standard API key
- **Proxy & SSL** support

---

## Async Pipeline Architecture

Each stream runs this pipeline concurrently:

```
┌─────────────────┐   page    ┌──────────────────┐  enqueue  ┌───────────────────┐
│  API fetch      │ ────────► │  processor-      │ ────────► │  QueueListener    │
│  thread         │           │  {stream} thread │           │  (file writer)    │
│                 │           │                  │  enqueue  ├───────────────────┤
│  HTTP req/resp  │           │  format_record() │ ────────► │  syslog-worker    │
│  put to         │           │  (CPU work)      │           │  (TCP/UDP sender) │
│  page_queue     │           │                  │           │                   │
└─────────────────┘           └──────────────────┘           └───────────────────┘
```

- `on_page()` is a pure non-blocking `queue.put()` — the fetch loop proceeds to the next HTTP request instantly
- File writes use Python's `QueueHandler` / `QueueListener` — caller enqueues in ~60 µs, background thread writes to disk
- Syslog sends enqueue in ~2 µs; a single background worker handles all TCP framing and delivery
- State is saved after every page, so partial progress survives mid-fetch failures

---

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`
- Docker (optional — for the bundled syslog receiver)

---

## Quick Start

```bash
cp .env.example .env
# Fill in api_key, api_key_id, and url
python cortex.py
```

---

## Configuration

All configuration is via `.env`. See `.env.example` for the full annotated reference.

| Variable | Description | Default |
|---|---|---|
| `api_key` | Cortex XDR API key | **required** |
| `api_key_id` | Cortex XDR API key ID | **required** |
| `url` | Cortex XDR tenant FQDN | **required** |
| `API_AUTH_TYPE` | `standard` or `advanced` | `standard` |
| `POLL_INTERVAL_SECONDS` | Seconds between poll cycles | `300` |
| `LOOKBACK_HOURS` | Hours to look back on first run (takes priority) | — |
| `LOOKBACK_DAYS` | Days to look back on first run | `1` |
| `STATE_FILE` | Path to state file | `./cortex_state.json` |
| `OUTPUT_FORMAT` | `leef`, `cef`, or `json` | `leef` |
| `ENABLE_FILE_LOG` | Write formatted records to rotating log files | `true` |
| `ENABLE_SYSLOG` | Forward records to syslog server | `false` |
| `LOG_DIR` | Alert log directory | `./logs/alerts` |
| `INCIDENTS_LOG_DIR` | Incident log directory | `./logs/incidents` |
| `AUDIT_MGMT_LOG_DIR` | Management audit log directory | `./logs/audit_mgmt` |
| `AUDIT_AGENT_LOG_DIR` | Agent audit log directory | `./logs/audit_agent` |
| `OPS_LOG_DIR` | Operational log directory | `./logs/ops` |
| `SYSLOG_HOST` | Syslog server hostname or IP | — |
| `SYSLOG_PORT` | Syslog server port | `514` |
| `SYSLOG_TRANSPORT` | `tcp` or `udp` | `tcp` |
| `SYSLOG_FACILITY` | Syslog facility (0–23) | `16` (local0) |
| `REQUEST_TIMEOUT_SECONDS` | HTTP timeout per page request | `60` |
| `REQUEST_MAX_RETRIES` | Retries per page with exponential backoff | `3` |
| `USE_PROXY` | Enable HTTP proxy | `false` |
| `PROXY_HTTP` | HTTP proxy URL | — |
| `PROXY_HTTPS` | HTTPS proxy URL | — |
| `SSL_VERIFY` | Verify TLS certificates | `true` |
| `DISPLAY_TZ_OFFSET` | UTC offset (hours) for rendered timestamps | `0` |

---

## Output Formats

| Format | Spec | Target SIEM |
|---|---|---|
| `leef` | LEEF 2.0 | IBM QRadar |
| `cef` | CEF 0 | ArcSight, Splunk, most SIEMs |
| `json` | Raw JSON with ISO timestamps | Any / custom pipelines |

---

## Data Streams

| Stream | API Endpoint | State Key | APP-NAME (syslog) |
|---|---|---|---|
| Alerts | `POST /public_api/v1/alerts/get_alerts` | `last_seen_alert_ts` | `cortex-alerts` |
| Incidents | `POST /public_api/v1/incidents/get_incidents` | `last_seen_incident_ts` | `cortex-incidents` |
| Mgmt Audits | `POST /public_api/v1/audits/management_logs` | `last_seen_mgmt_audit_ts` | `cortex-mgmt-audit` |
| Agent Audits | `POST /public_api/v1/audits/agents_reports` | `last_seen_agent_audit_ts` | `cortex-agent-audit` |

---

## Docker Syslog Receiver

A minimal RFC 5424 / RFC 6587 TCP syslog receiver is included for testing or lightweight deployments.

```bash
# Build
docker build -f Dockerfile.syslog -t cortex-syslog .

# Run — logs written to /tmp/cortex-syslog/received.log on the host
docker run -d \
  --name cortex-syslog \
  -p 5514:5514/tcp \
  -v /tmp/cortex-syslog:/logs \
  cortex-syslog
```

Then configure `.env`:

```
ENABLE_SYSLOG=true
SYSLOG_HOST=127.0.0.1
SYSLOG_PORT=5514
SYSLOG_TRANSPORT=tcp
```

Each stream's records arrive under its own `APP-NAME` field, making server-side filtering straightforward.

---

## File Structure

```
cortex.py               Entry point — starts 4 stream threads
config.py               All env-var loading and defaults
formatters.py           CEF / LEEF / JSON dispatch
leef.py                 LEEF 2.0 field maps and converters
logging_setup.py        Async QueueHandler file loggers + rotation
syslog_handler.py       Async RFC 5424 syslog sender (worker queue + TCP/UDP)
state.py                Atomic state file persistence
api_base.py             Paginated HTTP fetcher with retry + page_callback
api_alerts.py           Alerts endpoint
api_incidents.py        Incidents endpoint
api_mgmt_audit.py       Management audit endpoint
api_agent_audit.py      Agent audit endpoint
poller_base.py          Async poll engine (fetch thread + processor thread)
poller_alerts.py        Alerts poll cycle
poller_incidents.py     Incidents poll cycle
poller_mgmt_audit.py    Management audit poll cycle
poller_agent_audit.py   Agent audit poll cycle
syslog_receiver.py      Docker syslog receiver (RFC 6587 octet-count framing)
Dockerfile.syslog       Dockerfile for the syslog receiver
.env.example            Annotated configuration template
requirements.txt        Python dependencies
test_comprehensive.py   Full integration test suite (37 checks)
test_async_writes.py    Async pipeline benchmark + delivery test (22 checks)
test_alerts_incidents.py  Focused alerts & incidents test
```

---

## Log Rotation

Output files rotate:
- **Daily** at midnight UTC
- **Immediately** when the file reaches 100 MB

Up to 30 rotated files are retained per directory. All file writes are asynchronous — the poll thread never blocks on disk I/O.

---

## State File

`cortex_state.json` tracks the last-seen timestamp per stream:

```json
{
  "last_seen_alert_ts":      1711234567000,
  "last_seen_incident_ts":   1711234567000,
  "last_seen_mgmt_audit_ts": 1711234567000,
  "last_seen_agent_audit_ts":1711234567000
}
```

Timestamps are epoch milliseconds. State is written atomically (write-then-rename) after every API page, so a mid-fetch failure advances the cursor only for pages already delivered. Delete this file to force a full lookback re-fetch on the next run.

---

## Testing

```bash
# Full integration test — auth, pagination, ordering, state, threads,
# log integrity, Docker syslog delivery, async write benchmarks
python test_comprehensive.py

# Async pipeline benchmark + per-stream Docker syslog verification
python test_async_writes.py

# Focused alerts & incidents end-to-end test
python test_alerts_incidents.py
```

Tests are format-aware — pass `OUTPUT_FORMAT=cef` or `OUTPUT_FORMAT=json` as an environment variable to test all three formats:

```bash
OUTPUT_FORMAT=json python test_comprehensive.py
OUTPUT_FORMAT=cef  python test_comprehensive.py
```

All three formats pass **37/37** checks including exact-count Docker syslog delivery verification.
