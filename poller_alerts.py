from api_alerts import fetch_alerts
from logging_setup import alerts_leef_log
from poller_base import poll_stream


def poll_alerts_once(state: dict) -> dict:
    """
    One poll cycle for the Cortex XDR alerts stream.

    State key       : last_seen_alert_ts
    Timestamp field : detection_timestamp  (epoch ms; API filter uses creation_time but response field is detection_timestamp)
    Output file     : LOG_DIR/cortex_alerts.log
    Syslog APP-NAME : cortex-alerts
    Format          : determined by OUTPUT_FORMAT in config (leef/cef/json)
    """
    return poll_stream(
        state           = state,
        state_key       = "last_seen_alert_ts",
        fetch_fn        = fetch_alerts,
        stream          = "alerts",
        output_logger   = alerts_leef_log,
        ts_field        = "creation_time",
        label           = "alerts",
        syslog_app_name = "cortex-alerts",
    )
