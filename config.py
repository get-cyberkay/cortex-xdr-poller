import os
import sys
from dotenv import load_dotenv

load_dotenv()

_VALID_AUTH_TYPES = {"standard", "advanced"}


def _parse_int(name: str, default: int) -> int:
    """
    Parse an integer env var. Writes to stderr and uses the default if the
    value is present but not a valid integer. Does not raise — a bad env var
    must never crash the process at import time.
    """
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        sys.stderr.write(
            f"[ERROR] config: {name}={raw!r} is not a valid integer. "
            f"Using default value {default}.\n"
        )
        return default


# ---------------------------------------------------------------------------
# Cortex XDR API
# ---------------------------------------------------------------------------
API_KEY      = os.getenv("api_key", "")
API_KEY_ID   = os.getenv("api_key_id", "")
FQDN         = os.getenv("url", "")

_raw_auth_type = os.getenv("API_AUTH_TYPE", "standard").strip().lower()
if _raw_auth_type not in _VALID_AUTH_TYPES:
    sys.stderr.write(
        f"[ERROR] config: API_AUTH_TYPE={_raw_auth_type!r} is not valid. "
        f"Must be 'standard' or 'advanced'. Defaulting to 'standard'.\n"
    )
    _raw_auth_type = "standard"
API_AUTH_TYPE: str = _raw_auth_type

# ---------------------------------------------------------------------------
# Poller behaviour
# ---------------------------------------------------------------------------
POLL_INTERVAL  = _parse_int("POLL_INTERVAL_SECONDS", 300)
LOOKBACK_DAYS  = os.getenv("LOOKBACK_DAYS", "")
LOOKBACK_HOURS = os.getenv("LOOKBACK_HOURS", "")
STATE_FILE     = os.getenv("STATE_FILE", "./cortex_state.json")

# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------
OUTPUT_FORMAT = os.getenv("OUTPUT_FORMAT", "leef").strip().lower()

# ---------------------------------------------------------------------------
# Output flags
# ---------------------------------------------------------------------------
ENABLE_FILE_LOG = os.getenv("ENABLE_FILE_LOG", "true").strip().lower() == "true"
ENABLE_SYSLOG   = os.getenv("ENABLE_SYSLOG",   "false").strip().lower() == "true"

# ---------------------------------------------------------------------------
# Log directories
# ---------------------------------------------------------------------------
LOG_DIR             = os.getenv("LOG_DIR",             "./logs/leef")
INCIDENTS_LOG_DIR   = os.getenv("INCIDENTS_LOG_DIR",   "./logs/incidents")
AUDIT_MGMT_LOG_DIR  = os.getenv("AUDIT_MGMT_LOG_DIR",  "./logs/audit_mgmt")
AUDIT_AGENT_LOG_DIR = os.getenv("AUDIT_AGENT_LOG_DIR", "./logs/audit_agent")
OPS_LOG_DIR         = os.getenv("OPS_LOG_DIR",         "./logs/ops")

# ---------------------------------------------------------------------------
# Log rotation thresholds
# ---------------------------------------------------------------------------
LOG_MAX_BYTES    = 100 * 1024 * 1024
LOG_BACKUP_COUNT = 30

# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------
SYSLOG_HOST        = os.getenv("SYSLOG_HOST",        "")
SYSLOG_PORT        = _parse_int("SYSLOG_PORT",        514)
SYSLOG_TRANSPORT   = os.getenv("SYSLOG_TRANSPORT",   "tcp").strip().lower()
SYSLOG_TCP_FRAMING = os.getenv("SYSLOG_TCP_FRAMING", "newline").strip().lower()

# SYSLOG_HOSTNAME — optional. When non-empty, an RFC 3164 syslog header
#   (`<PRI>TIMESTAMP HOSTNAME `) is prepended to every payload, with this value
#   as the HOSTNAME field. QRadar (and most SIEMs) extract the Log Source
#   Identifier from that hostname token, so this lets you set an arbitrary,
#   stable identifier that is decoupled from the sending host's real IP/name.
#   Empty (default) → no header is added; the raw LEEF/CEF/JSON payload is sent
#   as-is and the log source is identified by packet source IP.
#
# SYSLOG_FACILITY — syslog facility (0–23) used to compute the RFC 3164 PRI.
#   Only relevant when SYSLOG_HOSTNAME is set. 16=local0 … 23=local7.
#   PRI = SYSLOG_FACILITY * 8 + 6 (severity 6 = informational).
SYSLOG_HOSTNAME    = os.getenv("SYSLOG_HOSTNAME", "").strip()
SYSLOG_FACILITY    = _parse_int("SYSLOG_FACILITY", 16)

# ---------------------------------------------------------------------------
# API pagination
# ---------------------------------------------------------------------------
PAGE_SIZE = 100

# ---------------------------------------------------------------------------
# Payload size limits
# ---------------------------------------------------------------------------
# MAX_FIELD_VALUE_LEN — maximum character length for any single list/dict field
#   value after serialisation to string. Fields exceeding this are truncated and
#   a [TRUNC] marker is appended. Default: 32 768 chars (32 KiB).
#
# SYSLOG_MAX_MSG_BYTES — hard ceiling on the encoded payload sent to syslog.
#   Any message exceeding this is truncated at the byte level and a [TRUNCATED]
#   marker is appended. Default: 32 MiB — QRadar's per-event size limit.
# ---------------------------------------------------------------------------
MAX_FIELD_VALUE_LEN  = _parse_int("MAX_FIELD_VALUE_LEN",  32_768)
SYSLOG_MAX_MSG_BYTES = _parse_int("SYSLOG_MAX_MSG_BYTES", 32 * 1024 * 1024)

# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
USE_PROXY   = os.getenv("USE_PROXY",   "false").strip().lower() == "true"
PROXY_HTTP  = os.getenv("PROXY_HTTP",  "")
PROXY_HTTPS = os.getenv("PROXY_HTTPS", "")

# ---------------------------------------------------------------------------
# SSL verification
# ---------------------------------------------------------------------------
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").strip().lower() != "false"

# ---------------------------------------------------------------------------
# HTTP request tuning
# ---------------------------------------------------------------------------
# REQUEST_TIMEOUT_SECONDS — how long to wait for the API to respond.
#   Default 60s. Increase if your network path to the Cortex XDR endpoint
#   is slow (corporate proxy, TLS inspection, high latency).
#
# REQUEST_MAX_RETRIES — how many times to retry a failed page request before
#   aborting the poll cycle. Default 3. Each retry is preceded by an
#   exponential backoff: 2s, 4s, 8s, ...
#   Set to 1 to disable retries (fail immediately on first error).
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = _parse_int("REQUEST_TIMEOUT_SECONDS", 60)
REQUEST_MAX_RETRIES     = _parse_int("REQUEST_MAX_RETRIES", 3)

# ---------------------------------------------------------------------------
# Display timezone for log output
# Timestamps from the Cortex XDR API are epoch milliseconds in UTC.
# DISPLAY_TIMEZONE controls how they are rendered in LEEF/CEF/JSON output.
# Format: UTC offset as a signed integer of hours, e.g.:
#   0   = UTC
#   1   = WAT (West Africa Time, UTC+1)
#   2   = CAT (Central Africa Time, UTC+2)
#   3   = EAT (East Africa Time, UTC+3)
#  -5   = EST (Eastern Standard Time, UTC-5)
# Default: 0 (UTC)
# ---------------------------------------------------------------------------
DISPLAY_TZ_OFFSET = _parse_int("DISPLAY_TZ_OFFSET", 0)
