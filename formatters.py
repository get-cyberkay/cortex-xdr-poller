r"""
formatters.py — CEF, LEEF, JSON, and QRadar output formatters.

Public interface
----------------
format_record(record: dict, stream: str) -> str
    Dispatch to the correct formatter based on OUTPUT_FORMAT from config.
    stream must be one of: "alerts", "incidents", "mgmt_audits", "agent_audits"

Individual formatters are also importable directly for testing:
    to_leef(record, stream)   -> str
    to_cef(record, stream)    -> str
    to_json(record, stream)   -> str
    to_qradar(record, stream) -> str
"""

import json
import logging
from datetime import datetime, timezone

import config as _config
from cef_utils import (
    cef_escape_header   as _cef_escape_header,
    cef_escape_ext_value as _cef_escape_ext_value,
    truncate_if_needed  as _truncate_if_needed,
    SEVERITY_MAP        as _SEVERITY_MAP,
)
from leef import (
    alert_to_leef, incident_to_leef,
    mgmt_audit_to_leef, agent_audit_to_leef,
    epoch_ms_to_iso,
    ALERT_EPOCH_MS_FIELDS, INCIDENT_EPOCH_MS_FIELDS,
    MGMT_AUDIT_EPOCH_MS_FIELDS, AGENT_AUDIT_EPOCH_MS_FIELDS,
    _has_value,
)
from qradar import to_qradar

log = logging.getLogger("cortex_poller")


# ---------------------------------------------------------------------------
# Stream → LEEF converter map (reuse leef.py entirely)
# ---------------------------------------------------------------------------
_LEEF_CONVERTERS = {
    "alerts":       alert_to_leef,
    "incidents":    incident_to_leef,
    "mgmt_audits":  mgmt_audit_to_leef,
    "agent_audits": agent_audit_to_leef,
}

# ---------------------------------------------------------------------------
# CEF field maps
# ---------------------------------------------------------------------------
_ALERT_CEF_EXT_MAP: dict[str, str] = {
    "alert_id":             "externalId",
    "name":                 "cat",
    "description":          "msg",
    "severity":             "sev",
    "action":               "act",
    "detection_timestamp":  "rt",   # event time (= API creation_time filter)
    "last_modified_ts":     "end",
    "host_name":            "dvc",
    "host_ip":              "src",
    "endpoint_id":          "cs1",
    "source":               "cs2",
    "category":             "cs3",
    "user_name":            "suser",
}

_INCIDENT_CEF_EXT_MAP: dict[str, str] = {
    "incident_id":               "externalId",
    "incident_name":             "cat",
    "description":               "msg",
    "severity":                  "sev",
    "status":                    "act",
    "creation_time":             "rt",
    "modification_time":         "end",
    "assigned_user_mail":        "suser",
    "assigned_user_pretty_name": "duser",
    "resolve_comment":           "cs1",
    "manual_description":        "cs2",
    "xdr_url":                   "cs3",
    "rule_based_score":          "cn1",
}

_MGMT_AUDIT_CEF_EXT_MAP: dict[str, str] = {
    "AUDIT_SOURCE_IP":   "src",
    "AUDIT_OWNER_EMAIL": "suser",
    "AUDIT_OWNER_NAME":  "suid",
    "AUDIT_RESULT":      "act",
    "AUDIT_DESCRIPTION": "msg",
    "AUDIT_INSERT_TIME": "rt",
    "AUDIT_HOSTNAME":    "dvc",
    "AUDIT_SESSION_ID":  "sessionId",
}

_AGENT_AUDIT_CEF_EXT_MAP: dict[str, str] = {
    "ENDPOINTNAME": "dvc",
    "DOMAIN":       "customerExternalID",
    "RESULT":       "act",
    "REASON":       "reason",
    "DESCRIPTION":  "msg",
    "TIMESTAMP":    "rt",
    "RECEIVEDTIME": "end",
}

_EPOCH_MS_FIELDS_BY_STREAM = {
    "alerts":       ALERT_EPOCH_MS_FIELDS,
    "incidents":    INCIDENT_EPOCH_MS_FIELDS,
    "mgmt_audits":  MGMT_AUDIT_EPOCH_MS_FIELDS,
    "agent_audits": AGENT_AUDIT_EPOCH_MS_FIELDS,
}

_CEF_EXT_MAP_BY_STREAM = {
    "alerts":       _ALERT_CEF_EXT_MAP,
    "incidents":    _INCIDENT_CEF_EXT_MAP,
    "mgmt_audits":  _MGMT_AUDIT_CEF_EXT_MAP,
    "agent_audits": _AGENT_AUDIT_CEF_EXT_MAP,
}

# ---------------------------------------------------------------------------
# CEF helpers
# ---------------------------------------------------------------------------

def _cef_severity(record: dict, stream: str) -> int:
    """
    Resolve CEF severity (0-10). Logs WARNING when a non-empty severity
    value is present but not in the known map — silent default would hide
    data quality issues in the source.
    """
    raw = record.get("severity") or record.get("AUDIT_SEVERITY") or ""
    normalised = str(raw).lower()
    if normalised in _SEVERITY_MAP:
        return _SEVERITY_MAP[normalised]
    if raw:
        log.warning(
            "_cef_severity [%s]: unrecognised severity value %r. "
            "Defaulting to 5 (medium).",
            stream, raw,
        )
    return 5


def _cef_signature_and_name(record: dict, stream: str) -> tuple[str, str]:
    """Return (SignatureID, Name) for the CEF header based on stream."""
    if stream == "alerts":
        sig  = str(record.get("alert_id", ""))
        name = str(record.get("name", "CortexAlert"))
    elif stream == "incidents":
        sig  = str(record.get("incident_id", ""))
        name = str(record.get("incident_name", "CortexIncident"))
    elif stream == "mgmt_audits":
        sig  = str(record.get("AUDIT_ID", ""))
        name = str(record.get("AUDIT_ENTITY", "MgmtAudit"))
    else:
        sig  = str(record.get("ENDPOINTID", ""))
        name = str(record.get("CATEGORY", "AgentAudit"))
    return _cef_escape_header(sig), _cef_escape_header(name)


# ---------------------------------------------------------------------------
# CEF formatter
# ---------------------------------------------------------------------------

def to_cef(record: dict, stream: str) -> str:
    """
    Convert a record dict to a CEF:0 log line.
    Logs WARNING for individual field conversion issues.
    Logs ERROR and re-raises on unexpected failure so the caller can skip.
    """
    try:
        sig_id, name = _cef_signature_and_name(record, stream)
        severity     = _cef_severity(record, stream)
        header       = f"CEF:0|PaloAlto|Cortex XDR|1.0|{sig_id}|{name}|{severity}|"

        ext_map      = _CEF_EXT_MAP_BY_STREAM[stream]
        epoch_fields = _EPOCH_MS_FIELDS_BY_STREAM[stream]

        mapped: dict[str, str]   = {}
        already_mapped: set[str] = set()
        custom: dict[str, str]   = {}

        for rec_key, cef_key in ext_map.items():
            if rec_key in record and _has_value(record[rec_key]):
                raw = record[rec_key]
                if cef_key in ("rt", "end"):
                    try:
                        mapped[cef_key] = str(int(raw))
                    except (TypeError, ValueError) as exc:
                        log.warning(
                            "to_cef [%s]: cannot convert timestamp field "
                            "%r=%r to int: %s. Raw string used.",
                            stream, rec_key, raw, exc,
                        )
                        mapped[cef_key] = _cef_escape_ext_value(str(raw))
                else:
                    mapped[cef_key] = _cef_escape_ext_value(str(raw))
                already_mapped.add(rec_key)

        for key, value in record.items():
            if key in already_mapped or not _has_value(value):
                continue
            if isinstance(value, (list, dict)):
                custom[key] = _truncate_if_needed(_cef_escape_ext_value(str(value)))
            elif key in epoch_fields:
                try:
                    custom[key] = str(int(value))
                except (TypeError, ValueError) as exc:
                    log.warning(
                        "to_cef [%s]: cannot convert epoch field %r=%r: %s.",
                        stream, key, value, exc,
                    )
                    custom[key] = _cef_escape_ext_value(str(value))
            else:
                custom[key] = _cef_escape_ext_value(str(value))

        ext_str = " ".join(f"{k}={v}" for k, v in {**mapped, **custom}.items())
        return header + ext_str

    except Exception as exc:
        log.error(
            "to_cef [%s]: unexpected failure converting record "
            "(first 5 keys: %s): %s",
            stream, list(record.keys())[:5], exc,
        )
        raise


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def to_json(record: dict, stream: str) -> str:
    """
    Serialise a record dict to a JSON string.
    Logs ERROR on serialisation failure and re-raises.
    """
    try:
        epoch_fields = _EPOCH_MS_FIELDS_BY_STREAM[stream]
        _primary_ts_keys = {
            "alerts":       {"detection_timestamp", "last_modified_ts", "local_insert_ts"},
            "incidents":    {"creation_time", "modification_time", "detection_time", "resolved_timestamp"},
            "mgmt_audits":  {"AUDIT_INSERT_TIME"},
            "agent_audits": {"TIMESTAMP", "RECEIVEDTIME"},
        }
        ts_keys = epoch_fields | _primary_ts_keys.get(stream, set())

        out = {}
        for key, value in record.items():
            if not _has_value(value):
                continue
            if key in ts_keys:
                out[key] = epoch_ms_to_iso(value)
            elif isinstance(value, list):
                serialised = json.dumps(value, ensure_ascii=False)
                if len(serialised) > _config.MAX_FIELD_VALUE_LEN:
                    out[key] = {
                        "_truncated": True,
                        "item_count": len(value),
                        "sample": value[:3],
                    }
                else:
                    out[key] = value
            elif isinstance(value, dict):
                serialised = json.dumps(value, ensure_ascii=False)
                if len(serialised) > _config.MAX_FIELD_VALUE_LEN:
                    out[key] = {
                        "_truncated": True,
                        "keys": list(value.keys()),
                    }
                else:
                    out[key] = value
            else:
                out[key] = value

        out["_stream"]   = stream
        out["_ingested"] = datetime.now(tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

        return json.dumps(out, ensure_ascii=False)

    except (TypeError, ValueError) as exc:
        log.error(
            "to_json [%s]: failed to serialise record. "
            "Record keys: %s. Error: %s",
            stream, list(record.keys()), exc,
        )
        raise


# ---------------------------------------------------------------------------
# LEEF formatter
# ---------------------------------------------------------------------------

def to_leef(record: dict, stream: str) -> str:
    """
    Dispatch to the appropriate leef.py converter for this stream.
    Logs ERROR if the stream label is not recognised.
    """
    converter = _LEEF_CONVERTERS.get(stream)
    if converter is None:
        log.error(
            "to_leef: unknown stream %r. Valid streams: %s.",
            stream, list(_LEEF_CONVERTERS),
        )
        raise ValueError(f"to_leef: unknown stream {stream!r}")
    return converter(record)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_DISPATCH = {
    "leef": to_leef,
    "cef":  to_cef,
    "json": to_json,
    "qradar": to_qradar,
}

_VALID_FORMATS = frozenset(_DISPATCH)


def format_record(record: dict, stream: str) -> str:
    """
    Convert record to the configured output format.
    Logs ERROR on invalid OUTPUT_FORMAT and raises ValueError.
    """
    fmt = _config.OUTPUT_FORMAT.strip().lower()
    if fmt not in _VALID_FORMATS:
        log.error(
            "format_record: OUTPUT_FORMAT=%r is invalid. "
            "Must be one of: %s.",
            fmt, sorted(_VALID_FORMATS),
        )
        raise ValueError(
            f"format_record: OUTPUT_FORMAT={fmt!r} is invalid. "
            f"Must be one of: {sorted(_VALID_FORMATS)}"
        )
    return _DISPATCH[fmt](record, stream)
