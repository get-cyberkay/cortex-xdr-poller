from datetime import datetime, timezone, timedelta
import logging

import config as _config

log = logging.getLogger("cortex_poller")

# ---------------------------------------------------------------------------
# LEEF field maps
# ---------------------------------------------------------------------------

# Alerts — POST /public_api/v1/alerts/get_alerts
ALERT_LEEF_FIELD_MAP: dict[str, str] = {
    "alert_id":             "eventId",
    "name":                 "cat",
    "description":          "reason",
    "severity":             "sev",
    "action":               "act",
    "detection_timestamp":  "devTime",    # when alert was detected (= API creation_time filter)
    "last_modified_ts":     "devTimeEnd", # last modification time
    "host_name":            "devName",
    "host_ip":              "src",
    "endpoint_id":          "cs1",
    "source":               "cs2",
    "category":             "cs3",
    "user_name":            "usrName",
}

ALERT_EPOCH_MS_FIELDS: set[str] = {
    "local_insert_ts",       # when the alert was ingested into XDR (custom extension)
    "end_match_attempt_ts",
    "resolved_timestamp",
}

# Incidents — POST /public_api/v1/incidents/get_incidents
INCIDENT_LEEF_FIELD_MAP: dict[str, str] = {
    "incident_id":               "eventId",
    "incident_name":             "cat",
    "description":               "reason",
    "severity":                  "sev",
    "status":                    "act",
    "creation_time":             "devTime",
    "modification_time":         "devTimeEnd",
    "assigned_user_mail":        "usrName",
    "assigned_user_pretty_name": "duser",
    "resolve_comment":           "cs1",
    "manual_description":        "cs2",
    "xdr_url":                   "cs3",
    "rule_based_score":          "cn1",
}

INCIDENT_EPOCH_MS_FIELDS: set[str] = {
    "detection_time",
    "resolved_timestamp",
}

# Management audit — POST /public_api/v1/audits/management_logs
MGMT_AUDIT_LEEF_FIELD_MAP: dict[str, str] = {
    "AUDIT_ID":              "eventId",
    "AUDIT_OWNER_EMAIL":     "usrName",
    "AUDIT_OWNER_NAME":      "userName",
    "AUDIT_SOURCE_IP":       "src",
    "AUDIT_ENTITY":          "cat",
    "AUDIT_ENTITY_SUBTYPE":  "catdt",
    "AUDIT_RESULT":          "act",
    "AUDIT_DESCRIPTION":     "reason",
    "AUDIT_SEVERITY":        "sev",
    "AUDIT_INSERT_TIME":     "devTime",
    "AUDIT_HOSTNAME":        "devName",
}

MGMT_AUDIT_EPOCH_MS_FIELDS: set[str] = set()

# Agent audit — POST /public_api/v1/audits/agents_reports
AGENT_AUDIT_LEEF_FIELD_MAP: dict[str, str] = {
    "ENDPOINTID":    "eventId",
    "ENDPOINTNAME":  "devName",
    "DOMAIN":        "domain",
    "CATEGORY":      "cat",
    "TYPE":          "catdt",
    "SUBTYPE":       "catdtSub",
    "RESULT":        "act",
    "REASON":        "reason",
    "DESCRIPTION":   "msg",
    "TIMESTAMP":     "devTime",
    "RECEIVEDTIME":  "devTimeEnd",
    "TRAPSVERSION":  "agentVersion",
}

AGENT_AUDIT_EPOCH_MS_FIELDS: set[str] = set()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_value(v) -> bool:
    """Return True only if the field carries meaningful content.

    Filters out None, empty strings, empty lists, and empty dicts so that
    blank fields are never emitted in any output format.
    """
    if v is None:
        return False
    if isinstance(v, (str, list, dict)) and len(v) == 0:
        return False
    return True


def sanitise(value) -> str:
    """Return a LEEF-safe string (no tabs, newlines, or pipes)."""
    if value is None:
        return ""
    text = str(value)
    for ch in ("\t", "\n", "\r", "|"):
        text = text.replace(ch, " ")
    return text


def epoch_to_iso(value) -> str:
    """
    Convert a Cortex XDR epoch-millisecond timestamp to a human-readable
    string in the configured display timezone (DISPLAY_TZ_OFFSET in .env).

    Cortex XDR timestamps are epoch milliseconds throughout.

    DISPLAY_TZ_OFFSET controls the output timezone:
      0  → UTC  (default)
      1  → WAT  (West Africa Time, UTC+1)
      2  → CAT  (Central Africa Time, UTC+2)
     -5  → EST  etc.

    Logs a warning when conversion fails so bad timestamps are visible.
    """
    try:
        from config import DISPLAY_TZ_OFFSET
        tz = timezone(timedelta(hours=DISPLAY_TZ_OFFSET))
        ts = int(value) / 1000
        return datetime.fromtimestamp(ts, tz=tz).strftime("%b %d %Y %H:%M:%S")
    except (TypeError, ValueError, OSError) as exc:
        log.warning(
            "epoch_to_iso: could not convert value %r to timestamp: %s. "
            "Raw value will be used.",
            value, exc,
        )
        return sanitise(value)


# Keep the old name as an alias so any external code still works.
epoch_ms_to_iso = epoch_to_iso


# ---------------------------------------------------------------------------
# Generic LEEF builder
# ---------------------------------------------------------------------------

def _build_leef(
    record: dict,
    event_id: str,
    field_map: dict[str, str],
    epoch_ms_fields: set[str],
) -> str:
    """
    Map known fields via field_map, convert timestamps, emit remaining
    fields as custom extensions. Lists and dicts are serialised to strings.
    """
    mapped: dict[str, str] = {}
    already_mapped: set[str] = set()
    custom: dict[str, str] = {}

    for record_key, leef_attr in field_map.items():
        if record_key in record and _has_value(record[record_key]):
            raw = record[record_key]
            if leef_attr in ("devTime", "devTimeEnd"):
                mapped[leef_attr] = epoch_to_iso(raw)
            else:
                mapped[leef_attr] = sanitise(raw)
            already_mapped.add(record_key)

    if "cat" not in mapped:
        mapped["cat"] = sanitise(event_id)

    for key, value in record.items():
        if key in already_mapped or not _has_value(value):
            continue
        if isinstance(value, (list, dict)):
            raw_str = sanitise(str(value))
            if len(raw_str) > _config.MAX_FIELD_VALUE_LEN:
                raw_str = raw_str[:_config.MAX_FIELD_VALUE_LEN] + "[TRUNC]"
            custom[key] = raw_str
        elif key in epoch_ms_fields:
            custom[key] = epoch_to_iso(value)
        else:
            custom[key] = sanitise(value)

    all_fields = {**mapped, **custom}
    return "|".join(f"{k}={v}" for k, v in all_fields.items())


# ---------------------------------------------------------------------------
# LEEF converters
# ---------------------------------------------------------------------------

def alert_to_leef(alert: dict) -> str:
    """Convert a single Cortex XDR alert dict to a LEEF 2.0 log line."""
    try:
        event_id = sanitise(str(alert.get("alert_id", "CortexAlert")))
        header   = f"LEEF:2.0|PaloAlto|Cortex XDR|1.0|{event_id}|x7c|"
        return header + _build_leef(
            record          = alert,
            event_id        = event_id,
            field_map       = ALERT_LEEF_FIELD_MAP,
            epoch_ms_fields = ALERT_EPOCH_MS_FIELDS,
        )
    except Exception as exc:
        log.error(
            "alert_to_leef: failed to convert alert_id=%r: %s",
            alert.get("alert_id"), exc,
        )
        raise


def incident_to_leef(incident: dict) -> str:
    """Convert a single Cortex XDR incident dict to a LEEF 2.0 log line."""
    try:
        event_id = sanitise(str(incident.get("incident_id", "CortexIncident")))
        header   = f"LEEF:2.0|PaloAlto|Cortex XDR|1.0|{event_id}|x7c|"
        return header + _build_leef(
            record          = incident,
            event_id        = event_id,
            field_map       = INCIDENT_LEEF_FIELD_MAP,
            epoch_ms_fields = INCIDENT_EPOCH_MS_FIELDS,
        )
    except Exception as exc:
        log.error(
            "incident_to_leef: failed to convert incident_id=%r: %s",
            incident.get("incident_id"), exc,
        )
        raise


def mgmt_audit_to_leef(record: dict) -> str:
    """Convert a single management audit log dict to a LEEF 2.0 log line."""
    try:
        event_id = sanitise(str(record.get("AUDIT_ID", "CortexMgmtAudit")))
        header   = f"LEEF:2.0|PaloAlto|Cortex XDR|1.0|{event_id}|x7c|"
        return header + _build_leef(
            record          = record,
            event_id        = event_id,
            field_map       = MGMT_AUDIT_LEEF_FIELD_MAP,
            epoch_ms_fields = MGMT_AUDIT_EPOCH_MS_FIELDS,
        )
    except Exception as exc:
        log.error(
            "mgmt_audit_to_leef: failed to convert AUDIT_ID=%r: %s",
            record.get("AUDIT_ID"), exc,
        )
        raise


def agent_audit_to_leef(record: dict) -> str:
    """Convert a single agent audit report dict to a LEEF 2.0 log line."""
    try:
        event_id = sanitise(record.get("ENDPOINTID", "CortexAgentAudit"))
        header   = f"LEEF:2.0|PaloAlto|Cortex XDR|1.0|{event_id}|x7c|"
        return header + _build_leef(
            record          = record,
            event_id        = event_id,
            field_map       = AGENT_AUDIT_LEEF_FIELD_MAP,
            epoch_ms_fields = AGENT_AUDIT_EPOCH_MS_FIELDS,
        )
    except Exception as exc:
        log.error(
            "agent_audit_to_leef: failed to convert ENDPOINTID=%r: %s",
            record.get("ENDPOINTID"), exc,
        )
        raise
