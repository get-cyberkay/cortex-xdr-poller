from api_agent_audit import fetch_agent_audits
from logging_setup import agent_audit_leef_log
from poller_base import poll_stream


def poll_agent_audits_once(state: dict) -> dict:
    """
    One poll cycle for the agent audit report stream.

    State key       : last_seen_agent_audit_ts
    Timestamp field : TIMESTAMP
    Output file     : AUDIT_AGENT_LOG_DIR/cortex_agent_audit.log
    Syslog APP-NAME : cortex-agent-audit
    Format          : determined by OUTPUT_FORMAT in config (leef/cef/json/qradar)
    """
    return poll_stream(
        state           = state,
        state_key       = "last_seen_agent_audit_ts",
        fetch_fn        = fetch_agent_audits,
        stream          = "agent_audits",
        output_logger   = agent_audit_leef_log,
        ts_field        = "TIMESTAMP",
        label           = "agent_audits",
        syslog_app_name = "cortex-agent-audit",
    )
