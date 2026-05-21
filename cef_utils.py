"""Shared CEF escape, severity, truncation, and stream-label utilities."""
import config as _config

STREAM_LABELS: dict[str, str] = {
    "alerts":       "Alert",
    "incidents":    "Incident",
    "mgmt_audits":  "ManagementAudit",
    "agent_audits": "AgentAudit",
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
