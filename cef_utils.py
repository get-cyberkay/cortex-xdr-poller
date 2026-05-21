"""Shared CEF escape, severity, truncation, and stream-label utilities."""
import config as _config

STREAM_LABELS: dict[str, str] = {
    "alerts":       "Alert",
    "incidents":    "Incident",
    "mgmt_audits":  "ManagementAudit",
    "agent_audits": "AgentAudit",
}

# Exact strings the QRadar DSM (device type 4001) matches in the CEF Product field
# and LEEF Product field to assign EventCategory. Must not be changed.
DSM_CATEGORIES: dict[str, str] = {
    "alerts":       "XDR Agent",
    "incidents":    "3rd Party",
    "mgmt_audits":  "Management Audit Logs",
    "agent_audits": "Agent Audit Logs",
}

SEVERITY_MAP: dict[str, int] = {
    "unknown":  1,
    "low":      3,
    "medium":   5,
    "high":     7,
    "critical": 10,
}


def cef_escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def cef_escape_ext_value(value: str) -> str:
    return (
        value
        .replace("\\", "\\\\")
        .replace("=",  "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def truncate_if_needed(value: str) -> str:
    if len(value) > _config.MAX_FIELD_VALUE_LEN:
        return value[:_config.MAX_FIELD_VALUE_LEN] + "[TRUNC]"
    return value
