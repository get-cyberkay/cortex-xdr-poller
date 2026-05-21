from api_mgmt_audit import fetch_mgmt_audits
from logging_setup import mgmt_audit_leef_log
from poller_base import poll_stream


def poll_mgmt_audits_once(state: dict) -> dict:
    """
    One poll cycle for the management audit log stream.

    State key       : last_seen_mgmt_audit_ts
    Timestamp field : AUDIT_INSERT_TIME
    Output file     : AUDIT_MGMT_LOG_DIR/cortex_mgmt_audit.log
    Syslog APP-NAME : cortex-mgmt-audit
    Format          : determined by OUTPUT_FORMAT in config (leef/cef/json/qradar)
    """
    return poll_stream(
        state           = state,
        state_key       = "last_seen_mgmt_audit_ts",
        fetch_fn        = fetch_mgmt_audits,
        stream          = "mgmt_audits",
        output_logger   = mgmt_audit_leef_log,
        ts_field        = "AUDIT_INSERT_TIME",
        label           = "mgmt_audits",
        syslog_app_name = "cortex-mgmt-audit",
    )
