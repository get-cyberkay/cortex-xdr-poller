from api_incidents import fetch_incidents
from logging_setup import incidents_leef_log
from poller_base import poll_stream


def poll_incidents_once(state: dict) -> dict:
    """
    One poll cycle for the Cortex XDR incidents stream.

    State key       : last_seen_incident_ts
    Timestamp field : modification_time  (epoch ms, from incidents response)
    Output file     : INCIDENTS_LOG_DIR/cortex_incidents.log
    Syslog APP-NAME : cortex-incidents
    Format          : determined by OUTPUT_FORMAT in config (leef/cef/json/qradar)

    Tracks modification_time so that updates to existing incidents (status
    changes, severity escalations, resolve comments) are captured on
    subsequent polls.
    """
    return poll_stream(
        state           = state,
        state_key       = "last_seen_incident_ts",
        fetch_fn        = fetch_incidents,
        stream          = "incidents",
        output_logger   = incidents_leef_log,
        ts_field        = "modification_time",
        label           = "incidents",
        syslog_app_name = "cortex-incidents",
    )
