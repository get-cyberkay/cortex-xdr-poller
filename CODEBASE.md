# Cortex XDR Poller — Agent Codebase Reference

## Purpose

A Python daemon that polls Cortex XDR APIs on a configurable interval, converts
records to LEEF, CEF, or JSON format, and writes them to rotating log files and/or
forwards them to a syslog server (RFC 5424) for ingestion into SIEMs such as IBM
QRadar, ArcSight, or Splunk.

Entry point: `python cortex.py`
Configuration: `.env` file (copy from `.env.example`)
Dependencies: `requests`, `python-dotenv` (see `requirements.txt`)
Python: 3.10+

---

## File Map

```
cortex.py              Entry point. Main loop. Orchestrates all 4 streams.
config.py              Loads all env vars. Single source of truth for settings.
formatters.py          Dispatches records to to_leef / to_cef / to_json.
leef.py                LEEF field maps, converters, and epoch→ISO helper.
logging_setup.py       Builds all rotating file handlers and the ops logger.
syslog_handler.py      RFC 5424 syslog sender (TCP persistent / UDP stateless).
state.py               Loads and saves cortex_state.json (atomic write).
api_base.py            Paginated HTTP fetcher with retry + exponential backoff.
api_alerts.py          Calls /public_api/v1/alerts/get_alerts
api_incidents.py       Calls /public_api/v1/incidents/get_incidents
api_mgmt_audit.py      Calls /public_api/v1/audits/management_logs
api_agent_audit.py     Calls /public_api/v1/audits/agents_reports
poller_base.py         Shared poll cycle engine used by all 4 stream pollers.
poller_alerts.py       Alerts poll cycle.
poller_incidents.py    Incidents poll cycle.
poller_mgmt_audit.py   Management audit poll cycle.
poller_agent_audit.py  Agent audit poll cycle.
cortex_plain.py        One-off throwaway script used during early API exploration.
                       Not part of the daemon. Not imported anywhere.
```

---

## Execution Flow

```
cortex.py main()
  └─ load_state()                        # reads cortex_state.json
  └─ loop forever:
       for each stream in [alerts, incidents, mgmt_audits, agent_audits]:
         poll_fn(state)                  # poller_*.py
           └─ poll_stream(...)           # poller_base.py
                └─ compute_lookback_ts() # first run only — LOOKBACK_HOURS > LOOKBACK_DAYS > 24h
                └─ fetch_fn(since_ts)    # api_*.py → api_base.fetch_all()
                     └─ paginated HTTP POST with retry + backoff
                └─ for each record:
                     format_record()     # formatters.py → leef/cef/json
                     output_logger.info() # rotating file
                     send_syslog()       # syslog_handler.py (no-op if disabled)
                └─ save_state()         # updates state key with max ts seen
       sleep POLL_INTERVAL_SECONDS
```

---

## The 4 Data Streams

Each stream follows an identical pattern. The differences are captured here.

| Stream | API Endpoint | state_key | ts_field (cursor) | reply_key | count_key | Log File | Syslog APP-NAME |
|---|---|---|---|---|---|---|---|
| alerts | `/public_api/v1/alerts/get_alerts` | `last_seen_alert_ts` | `local_insert_ts` | `alerts` | `total_count` | `cortex_alerts.log` | `cortex-alerts` |
| incidents | `/public_api/v1/incidents/get_incidents` | `last_seen_incident_ts` | `modification_time` | `incidents` | `total_count` | `cortex_incidents.log` | `cortex-incidents` |
| mgmt_audits | `/public_api/v1/audits/management_logs` | `last_seen_mgmt_audit_ts` | `AUDIT_INSERT_TIME` | `data` | `total_count` | `cortex_mgmt_audit.log` | `cortex-mgmt-audit` |
| agent_audits | `/public_api/v1/audits/agents_reports` | `last_seen_agent_audit_ts` | `TIMESTAMP` | `data` | `total_count` | `cortex_agent_audit.log` | `cortex-agent-audit` |

**Stream-specific notes:**
- Alerts filters and sorts by `local_insert_ts` (the time each alert was inserted).
- Incidents filters by `modification_time` so that status changes, severity escalations,
  and resolve comments on existing incidents are captured on subsequent polls. An incident
  may therefore appear more than once in output over its lifetime.
- The audit endpoints filter/sort using the API field name `timestamp`, but the cursor
  reads the response field: `AUDIT_INSERT_TIME` (mgmt) and `TIMESTAMP` (agent).
  These are the same underlying value under different key names.

---

## Authentication (`api_base.build_headers`)

Controlled by `API_AUTH_TYPE`. Headers are generated fresh on every HTTP request (required for advanced auth).

**Standard** (`API_AUTH_TYPE=standard`, default):
```
Authorization:   <api_key>
x-xdr-auth-id:  <api_key_id>
```

**Advanced** (`API_AUTH_TYPE=advanced`):
```
Authorization:   SHA-256(api_key + nonce + timestamp_ms)
x-xdr-auth-id:  <api_key_id>
x-xdr-nonce:    <64-char random alphanumeric string, unique per request>
x-xdr-timestamp: <current epoch milliseconds>
```

Use `standard` when the key was created as a Standard key in the Cortex XDR console.
Use `advanced` when the key was created as an Advanced key.

---

## API Pagination (`api_base.py`)

All four streams use `fetch_all()`, which pages through results in batches of `PAGE_SIZE=100`.

Request body structure (sent as `{"request_data": {...}}`):
```json
{
  "filters": [{"field": "<time_field>", "operator": "gte", "value": <since_ts>}],
  "sort":    {"field": "<time_field>", "keyword": "asc"},
  "search_from": 0,
  "search_to":   100
}
```

**Retry logic:** `_fetch_page()` wraps `_fetch_page_once()` with up to `REQUEST_MAX_RETRIES`
attempts (default 3). Backoff: attempt 1 → immediate, attempt 2 → 2s, attempt 3 → 4s.

**Result-set cap:** The API silently caps results at 9999 records per query. If
`total_count >= 9999`, a WARNING is logged advising to reduce `LOOKBACK_DAYS` or
`POLL_INTERVAL_SECONDS`. Records beyond 9999 will be missed.

**None vs []:** `fetch_all` returns `None` on any page failure (state must NOT be
advanced) and `[]` on a clean empty poll (state is left unchanged, no log written).

**Error patterns handled:**
- `SSLError`, `ConnectionError`, `Timeout`, `HTTPError` → logged with specific guidance
- API-level errors: `reply.err_code/err_msg` (XDR pattern) and `data.error` (XSIAM pattern)
- JSON decode failure

---

## State Persistence (`state.py`)

File: `cortex_state.json` (path from `STATE_FILE` env var, default `./cortex_state.json`)

```json
{
  "last_seen_alert_ts":      1711234567000,
  "last_seen_incident_ts":   1711234567000,
  "last_seen_mgmt_audit_ts": 1711234567000,
  "last_seen_agent_audit_ts":1711234567000
}
```

All timestamps are epoch **milliseconds**.

State is only updated after a fully successful paginated fetch. A partial fetch (any
page returns `None`) leaves the state unchanged so the next poll retries from the
same `since_ts`.

`save_state()` uses a write-then-`os.replace()` pattern — a partial write can never
corrupt the existing state file.

Delete the file to force a full lookback re-fetch on the next start.

---

## Lookback on First Run (`poller_base.compute_lookback_ts`)

Priority order:
1. `LOOKBACK_HOURS` (accepts floats, e.g. `1.5`)
2. `LOOKBACK_DAYS` (accepts floats)
3. Default: 24 hours

Applied independently per stream on the first poll (when the stream's state key is
absent). Bad values log ERROR and fall through to the next option rather than crashing.

---

## Output Formats (`formatters.py`, `leef.py`)

Controlled by `OUTPUT_FORMAT` env var. Applied uniformly across all streams.

### LEEF 2.0
Header: `LEEF:2.0|PaloAlto|Cortex XDR|1.0|<eventId>|x7c|`
Fields are pipe-delimited `key=value` pairs. Tab, newline, pipe, and carriage return
in values are replaced with spaces (`sanitise()`). Timestamp fields (`devTime`,
`devTimeEnd`) are converted from epoch-ms to human-readable via `epoch_to_iso()`.

### CEF:0
Header: `CEF:0|PaloAlto|Cortex XDR|1.0|<sigId>|<name>|<severity>|`
Extension is space-delimited `key=value`. Values escape `\`, `=`, `\n`, `\r`.
Timestamp fields (`rt`, `end`) are kept as raw epoch-ms integers (per CEF spec).
Severity is mapped: `unknown=1, low=3, medium=5, high=7, critical=10`.

### JSON
Each record is serialised to a single JSON line. All epoch-ms timestamp fields are
converted to ISO 8601 strings. Two metadata fields are injected:
- `_stream`: stream name (e.g. `"alerts"`)
- `_ingested`: UTC ISO timestamp of when the record was written

### Display Timezone
`DISPLAY_TZ_OFFSET` (integer hours, default `0` = UTC) controls how epoch-ms
timestamps are rendered in LEEF and JSON output. Examples: `1`=WAT, `2`=CAT, `3`=EAT.

### LEEF Field Maps (summary)

**Alerts** (`/public_api/v1/alerts/get_alerts`):
`alert_id→eventId, name→cat, description→reason, severity→sev, action→act,`
`local_insert_ts→devTime, last_modified_ts→devTimeEnd, host_name→devName,`
`host_ip→src, endpoint_id→cs1, source→cs2, category→cs3, user_name→usrName`

Additional epoch-ms fields converted as custom extensions:
`detection_timestamp, end_match_attempt_ts, resolved_timestamp`

**Incidents** (`/public_api/v1/incidents/get_incidents`):
`incident_id→eventId, incident_name→cat, description→reason, severity→sev,`
`status→act, creation_time→devTime, modification_time→devTimeEnd,`
`assigned_user_mail→usrName, assigned_user_pretty_name→duser,`
`resolve_comment→cs1, manual_description→cs2, xdr_url→cs3, rule_based_score→cn1`

Additional epoch-ms fields converted as custom extensions:
`detection_time, resolved_timestamp`

**Mgmt Audits** (`/public_api/v1/audits/management_logs`):
`AUDIT_ID→eventId, AUDIT_OWNER_EMAIL→usrName, AUDIT_OWNER_NAME→userName,`
`AUDIT_SOURCE_IP→src, AUDIT_ENTITY→cat, AUDIT_ENTITY_SUBTYPE→catdt,`
`AUDIT_RESULT→act, AUDIT_DESCRIPTION→reason, AUDIT_SEVERITY→sev,`
`AUDIT_INSERT_TIME→devTime, AUDIT_HOSTNAME→devName`

**Agent Audits** (`/public_api/v1/audits/agents_reports`):
`ENDPOINTID→eventId, ENDPOINTNAME→devName, DOMAIN→domain, CATEGORY→cat,`
`TYPE→catdt, SUBTYPE→catdtSub, RESULT→act, REASON→reason, DESCRIPTION→msg,`
`TIMESTAMP→devTime, RECEIVEDTIME→devTimeEnd, TRAPSVERSION→agentVersion`

Unmapped fields from all streams are passed through as custom extensions.

---

## Audit Stream Verification Against PDF Spec

Both audit streams were verified against the Cortex XDR REST API specification PDF
(`managementaudit&endpointauditapispecification.pdf`).

**Management Audit** — fully compliant:
- Endpoint: `POST /public_api/v1/audits/management_logs` ✓
- Reply key: `data` ✓ (spec: `reply.data`)
- API filter/sort field: `timestamp` ✓ (spec example: `"field": "timestamp"`)
- Response cursor field: `AUDIT_INSERT_TIME` ✓ (same epoch-ms value, different key name)
- Response fields: all covered by LEEF map ✓

**Agent Audit** — fully compliant:
- Endpoint: `POST /public_api/v1/audits/agents_reports` ✓
- Reply key: `data` ✓ (spec: `reply.data`)
- API filter/sort field: `timestamp` ✓ (spec example: `"field": "timestamp"`)
- Response cursor field: `TIMESTAMP` ✓
- Response fields (`TIMESTAMP`, `RECEIVEDTIME`, `ENDPOINTID`, `ENDPOINTNAME`,
  `DOMAIN`, `TRAPSVERSION`, `CATEGORY`, `TYPE`, `SUBTYPE`, `RESULT`, `REASON`,
  `DESCRIPTION`): all covered by LEEF map ✓

---

## Logging (`logging_setup.py`)

### Output (LEEF/CEF/JSON) Loggers
One per stream. All use `_SizedTimedRotatingFileHandler`:
- Rotates daily at midnight UTC
- Also rotates immediately when file reaches `LOG_MAX_BYTES` (100 MB)
- Retains `LOG_BACKUP_COUNT=30` rotated files
- Falls back to `NullHandler` if `ENABLE_FILE_LOG=false` or directory/file creation fails

| Logger name | Default path | File |
|---|---|---|
| `cortex_alerts` | `LOG_DIR` (`./logs/leef`) | `cortex_alerts.log` |
| `cortex_incidents` | `INCIDENTS_LOG_DIR` (`./logs/incidents`) | `cortex_incidents.log` |
| `cortex_mgmt_audit` | `AUDIT_MGMT_LOG_DIR` (`./logs/audit_mgmt`) | `cortex_mgmt_audit.log` |
| `cortex_agent_audit` | `AUDIT_AGENT_LOG_DIR` (`./logs/audit_agent`) | `cortex_agent_audit.log` |

### Operational Logger (`log = logging.getLogger("cortex_poller")`)
Three handlers simultaneously:
- `cortex_info.log` — INFO level only (filtered with `_MaxLevelFilter`)
- `cortex_error.log` — WARNING and above (filtered with `_MinLevelFilter`)
- stderr — all levels (for Docker / systemd / service managers)

All operational logs go to `OPS_LOG_DIR` (`./logs/ops`).

---

## Syslog (`syslog_handler.py`)

`send_syslog(msg, app_name)` is a no-op when `ENABLE_SYSLOG=false` or `SYSLOG_HOST`
is unset.

**RFC 5424 format:**
```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PID - - MSG
```
- PRI = `SYSLOG_FACILITY * 8 + 6` (INFO severity)
- STRUCTURED-DATA is always `-` (nil) — all data is in the LEEF/CEF/JSON message
- APP-NAME is truncated to 48 chars per spec

**TCP (default):** A single module-level socket is reused. On send failure: close,
reconnect, retry once. If reconnect also fails, the message is dropped and an ERROR
is logged. Uses RFC 6587 octet-count framing: `<len> <msg>`.

**UDP:** Stateless `sendto` per message. No persistent socket.

`send_syslog` never raises — all failures are logged and swallowed so that a dead
syslog server cannot interrupt the poll loop.

---

## Configuration Reference (`config.py`)

| Variable | Default | Notes |
|---|---|---|
| `api_key` | — | Cortex XDR API key |
| `api_key_id` | — | Cortex XDR API key ID (x-xdr-auth-id header) |
| `url` | — | Tenant FQDN, e.g. `https://api-xyz.xdr.us.paloaltonetworks.com` |
| `API_AUTH_TYPE` | `standard` | `standard` or `advanced` — controls how the Authorization header is built (see below) |
| `POLL_INTERVAL_SECONDS` | `300` | Seconds to sleep between full poll cycles |
| `LOOKBACK_HOURS` | — | Hours to look back on first run (float accepted) |
| `LOOKBACK_DAYS` | — | Days to look back on first run (float accepted, fallback) |
| `STATE_FILE` | `./cortex_state.json` | Path to state persistence file |
| `OUTPUT_FORMAT` | `leef` | `leef`, `cef`, or `json` |
| `ENABLE_FILE_LOG` | `true` | Write formatted records to rotating log files |
| `ENABLE_SYSLOG` | `false` | Forward formatted records to syslog server |
| `LOG_DIR` | `./logs/leef` | Alerts output directory |
| `INCIDENTS_LOG_DIR` | `./logs/incidents` | Incidents output directory |
| `AUDIT_MGMT_LOG_DIR` | `./logs/audit_mgmt` | Mgmt audit output directory |
| `AUDIT_AGENT_LOG_DIR` | `./logs/audit_agent` | Agent audit output directory |
| `OPS_LOG_DIR` | `./logs/ops` | Operational (info/error) log directory |
| `SYSLOG_HOST` | — | Syslog server hostname or IP |
| `SYSLOG_PORT` | `514` | Syslog server port |
| `SYSLOG_TRANSPORT` | `tcp` | `tcp` or `udp` |
| `SYSLOG_FACILITY` | `16` | RFC 5424 facility integer (16 = local0) |
| `REQUEST_TIMEOUT_SECONDS` | `60` | HTTP request timeout |
| `REQUEST_MAX_RETRIES` | `3` | Max retry attempts per page request |
| `DISPLAY_TZ_OFFSET` | `0` | Hours offset from UTC for timestamp display |
| `USE_PROXY` | `false` | Route HTTP through a proxy |
| `PROXY_HTTP` | — | HTTP proxy URL |
| `PROXY_HTTPS` | — | HTTPS proxy URL |
| `SSL_VERIFY` | `true` | TLS cert verification. Set `false` only for TLS-inspecting proxies. |
| `PAGE_SIZE` | `100` | (hardcoded in config.py, not env-configurable) |

---

## `cortex_plain.py` — Scratch Script

A standalone one-off script created during early API exploration. It fetches a
handful of issues using a hardcoded timestamp filter and pretty-prints the raw JSON
response. It is **not** part of the daemon and is **not imported** anywhere.

---

## Key Invariants and Gotchas

1. **All Cortex XDR timestamps are epoch milliseconds**, not seconds. The
   `epoch_to_iso()` function always divides by 1000 before calling `datetime.fromtimestamp`.

2. **State only advances on full success.** If any page in a paginated fetch fails,
   `fetch_all` returns `None` and `poll_stream` returns the state unchanged. The next
   poll retries from the same `since_ts`. This prevents silent data loss but means
   records already formatted in a failed cycle are discarded and will be re-fetched.

3. **Format failures skip the record but advance the cursor.** A record that raises
   in `format_record()` is counted as `skipped`, not `written`. The `max_ts` is only
   updated for records that reach the `written += 1` line, so a persistently bad record
   will be re-fetched indefinitely if it is the newest record in a cycle.

4. **File write failures do not skip syslog.** If `output_logger.info()` raises, the
   error is logged but syslog delivery is still attempted for that record.

5. **The 9999-record API cap is silent.** The API does not return an error — it just
   stops at 9999. The poller detects this and logs a WARNING, but records beyond the
   cap are silently missed unless the poll interval or lookback is reduced.

6. **SSL_VERIFY=false** logs a WARNING at import time and should never be used in
   production. It exists solely for environments with TLS-inspecting proxies.

7. **Incidents use `modification_time` as the cursor**, not `creation_time`. This means
   that updated incidents are re-emitted on subsequent polls. This is intentional —
   status changes and resolution details should be forwarded to the SIEM — but it means
   an incident may appear multiple times in output over its lifetime.

8. **Audit endpoints use different field names for filtering vs response.** The API
   accepts `timestamp` as the filter/sort field, but returns the same value as
   `AUDIT_INSERT_TIME` (mgmt) and `TIMESTAMP` (agent) in the response body. The poller
   correctly uses `timestamp` for the API request and reads the response field for the
   state cursor.
