from __future__ import annotations

from datetime import datetime, timezone
import logging

import config as _config
from cef_utils import (
    cef_escape_header    as _cef_escape_header,
    cef_escape_ext_value as _cef_escape_ext_value,
    truncate_if_needed   as _truncate_if_needed,
    SEVERITY_MAP         as _SEVERITY_MAP,
    STREAM_LABELS        as _STREAM_LABELS,
)
from leef import _has_value

log = logging.getLogger("cortex_poller")


# ---------------------------------------------------------------------------
# QRadar DSM-compatible categories
# ---------------------------------------------------------------------------

QRADAR_CATEGORIES = {
    "alerts_default": "XDR Agent",
    "mgmt_audits":    "Management Audit Logs",
    "agent_audits":   "Agent Audit Logs",
    "incidents":      "3rd Party",
}


def _epoch_ms_to_qradar_iso(value) -> str:
    """
    Render timestamps in the ISO layout expected by the imported DSM extension.
    """
    try:
        ts = int(value) / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError, OSError):
        return _cef_escape_ext_value(str(value))


def _severity_to_cef(value) -> int:
    normalised = str(value or "").strip().lower()
    return _SEVERITY_MAP.get(normalised, 5)


def _choose_first(record: dict, *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if _has_value(value):
            return str(value)
    return ""


def _alert_category(record: dict) -> str:
    haystack = " ".join(
        str(record.get(k, ""))
        for k in ("source", "category", "name", "description")
    ).lower()

    if "analytics" in haystack and "bioc" in haystack:
        return "XDR Analytics BIOC"
    if "bioc" in haystack:
        return "XDR BIOC"
    if "ioc" in haystack:
        return "XDR IOC"
    if "ngfw" in haystack or "firewall" in haystack:
        return "PAN NGFW"
    if "agent" in haystack:
        return "XDR Agent"
    return QRADAR_CATEGORIES["alerts_default"]


def _stream_product(record: dict, stream: str) -> str:
    if stream == "alerts":
        return _alert_category(record)
    return QRADAR_CATEGORIES.get(stream, "3rd Party")


def _event_name(record: dict, stream: str) -> str:
    if stream == "alerts":
        return _choose_first(record, "category", "name", "source", "alert_id") or "Alert"
    if stream == "incidents":
        return _choose_first(record, "incident_name", "status", "incident_id") or "Incident"
    if stream == "mgmt_audits":
        return _choose_first(record, "AUDIT_ENTITY_SUBTYPE", "AUDIT_ENTITY", "AUDIT_ID") or "Management Audit"
    if stream == "agent_audits":
        return _choose_first(record, "CATEGORY", "TYPE", "SUBTYPE", "ENDPOINTID") or "Agent Audit"
    return stream


def _signature_id(record: dict, stream: str) -> str:
    if stream == "alerts":
        return _choose_first(record, "alert_id") or "CortexAlert"
    if stream == "incidents":
        return _choose_first(record, "incident_id") or "CortexIncident"
    if stream == "mgmt_audits":
        return _choose_first(record, "AUDIT_ID") or "CortexMgmtAudit"
    if stream == "agent_audits":
        return _choose_first(record, "ENDPOINTID") or "CortexAgentAudit"
    return stream


def _hostname(record: dict, stream: str) -> str:
    if stream in ("alerts", "incidents"):
        return _choose_first(record, "host_name")
    if stream == "mgmt_audits":
        return _choose_first(record, "AUDIT_HOSTNAME")
    if stream == "agent_audits":
        return _choose_first(record, "ENDPOINTNAME")
    return ""


def _username(record: dict, stream: str) -> str:
    if stream == "alerts":
        return _choose_first(record, "user_name")
    if stream == "incidents":
        return _choose_first(record, "assigned_user_mail", "assigned_user_pretty_name")
    if stream == "mgmt_audits":
        return _choose_first(record, "AUDIT_OWNER_EMAIL", "AUDIT_OWNER_NAME")
    if stream == "agent_audits":
        return _choose_first(record, "DOMAIN")
    return ""


def _primary_timestamp(record: dict, stream: str):
    if stream == "alerts":
        return record.get("detection_timestamp") or record.get("last_modified_ts")
    if stream == "incidents":
        return record.get("modification_time") or record.get("creation_time")
    if stream == "mgmt_audits":
        return record.get("AUDIT_INSERT_TIME")
    if stream == "agent_audits":
        return record.get("TIMESTAMP") or record.get("RECEIVEDTIME")
    return None


def _end_timestamp(record: dict, stream: str):
    if stream == "alerts":
        return record.get("last_modified_ts")
    if stream == "incidents":
        return record.get("modification_time")
    if stream == "agent_audits":
        return record.get("RECEIVEDTIME")
    return None


def _base_extensions(record: dict, stream: str) -> dict[str, str]:
    event_name = _event_name(record, stream)
    ext: dict[str, str] = {
        "cat": event_name,
        "qradarCategory": _stream_product(record, stream),
    }

    hostname = _hostname(record, stream)
    username = _username(record, stream)
    if hostname:
        ext["shost"] = hostname
    if username:
        ext["suser"] = username

    primary_ts = _primary_timestamp(record, stream)
    if _has_value(primary_ts):
        ext["start"] = _epoch_ms_to_qradar_iso(primary_ts)
        ext["rt"] = str(int(primary_ts))

    end_ts = _end_timestamp(record, stream)
    if _has_value(end_ts):
        ext["end"] = str(int(end_ts))

    # Preserve the original source identifiers for analyst workflows.
    for key in ("alert_id", "incident_id", "AUDIT_ID", "ENDPOINTID"):
        if _has_value(record.get(key)):
            ext[key] = str(record[key])

    return ext


def _stream_specific_extensions(record: dict, stream: str) -> dict[str, str]:
    if stream == "alerts":
        return {
            "act": _choose_first(record, "action"),
            "reason": _choose_first(record, "description"),
            "sev": _choose_first(record, "severity"),
            "src": _choose_first(record, "host_ip"),
            "source": _choose_first(record, "source"),
            "category": _choose_first(record, "category"),
            "endpoint_id": _choose_first(record, "endpoint_id"),
            "name": _choose_first(record, "name"),
        }
    if stream == "incidents":
        return {
            "act": _choose_first(record, "status"),
            "reason": _choose_first(record, "description"),
            "sev": _choose_first(record, "severity"),
            "assigned_user_pretty_name": _choose_first(record, "assigned_user_pretty_name"),
            "resolve_comment": _choose_first(record, "resolve_comment"),
            "manual_description": _choose_first(record, "manual_description"),
            "xdr_url": _choose_first(record, "xdr_url"),
        }
    if stream == "mgmt_audits":
        return {
            "act": _choose_first(record, "AUDIT_RESULT"),
            "reason": _choose_first(record, "AUDIT_DESCRIPTION"),
            "sev": _choose_first(record, "AUDIT_SEVERITY"),
            "src": _choose_first(record, "AUDIT_SOURCE_IP"),
            "AUDIT_ENTITY": _choose_first(record, "AUDIT_ENTITY"),
            "AUDIT_ENTITY_SUBTYPE": _choose_first(record, "AUDIT_ENTITY_SUBTYPE"),
        }
    if stream == "agent_audits":
        return {
            "act": _choose_first(record, "RESULT"),
            "reason": _choose_first(record, "REASON"),
            "msg": _choose_first(record, "DESCRIPTION"),
            "TYPE": _choose_first(record, "TYPE"),
            "SUBTYPE": _choose_first(record, "SUBTYPE"),
            "TRAPSVERSION": _choose_first(record, "TRAPSVERSION"),
        }
    return {}


def _serialise_value(value) -> str:
    if isinstance(value, (list, dict)):
        return _truncate_if_needed(_cef_escape_ext_value(str(value)))
    return _cef_escape_ext_value(str(value))


def to_qradar(record: dict, stream: str) -> str:
    """
    Build a QRadar DSM-compatible CEF event. The DSM extension matches literal
    product markers such as |XDR Agent| and extracts cat/shost/suser from the
    CEF extensions.
    """
    product = _stream_product(record, stream)
    event_name = _event_name(record, stream)
    signature_id = _signature_id(record, stream)
    severity = _severity_to_cef(
        record.get("severity") or record.get("AUDIT_SEVERITY")
    )

    header = (
        "CEF:0|PaloAlto|"
        f"{_cef_escape_header(product)}|"
        f"{_cef_escape_header(event_name)}|"
        f"{_cef_escape_header(signature_id)}|"
        f"{_cef_escape_header(event_name)}|"
        f"{severity}|"
    )

    ext: dict[str, str] = {"stream": _STREAM_LABELS.get(stream, stream)}
    for key, value in {**_base_extensions(record, stream), **_stream_specific_extensions(record, stream)}.items():
        if _has_value(value):
            ext[key] = _serialise_value(value)

    # Pass through remaining fields that are not already emitted.
    for key, value in record.items():
        if key in ext or not _has_value(value):
            continue
        ext[key] = _serialise_value(value)

    ext_str = " ".join(f"{key}={value}" for key, value in ext.items())
    return header + ext_str
