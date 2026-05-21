"""Shared CEF escape, severity, and truncation utilities for formatters.py and qradar.py."""
import config as _config

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
