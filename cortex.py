"""
cortex.py — entry point for the Cortex XDR LEEF/CEF/JSON poller.

Data streams:
  alerts       — POST /public_api/v1/alerts/get_alerts
  incidents    — POST /public_api/v1/incidents/get_incidents
  mgmt_audits  — POST /public_api/v1/audits/management_logs
  agent_audits — POST /public_api/v1/audits/agents_reports

Each stream runs in its own daemon thread so all four polls are independent.
One slow or failing stream does not delay the others.
"""
import sys
import time
import threading

from config import (
    POLL_INTERVAL, OUTPUT_FORMAT,
    LOG_DIR, INCIDENTS_LOG_DIR,
    AUDIT_MGMT_LOG_DIR, AUDIT_AGENT_LOG_DIR,
    OPS_LOG_DIR, STATE_FILE,
)
from formatters import _VALID_FORMATS
from leef import epoch_ms_to_iso
from logging_setup import log
from poller_alerts      import poll_alerts_once
from poller_incidents   import poll_incidents_once
from poller_mgmt_audit  import poll_mgmt_audits_once
from poller_agent_audit import poll_agent_audits_once
from state import load_state


_STREAMS = [
    (poll_alerts_once,       "last_seen_alert_ts",      "Alerts"),
    (poll_incidents_once,    "last_seen_incident_ts",   "Incidents"),
    (poll_mgmt_audits_once,  "last_seen_mgmt_audit_ts", "Mgmt Audits"),
    (poll_agent_audits_once, "last_seen_agent_audit_ts","Agent Audits"),
]


def _stream_loop(poll_fn, state: dict, label: str) -> None:
    """
    Thread target for a single data stream.

    Runs poll_fn in an infinite loop, sleeping POLL_INTERVAL seconds between
    cycles. Unhandled exceptions are logged but never propagate — the stream
    restarts on the next interval rather than killing the thread.
    """
    while True:
        try:
            poll_fn(state)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "main [%s]: unhandled exception in poll cycle: %s",
                label, exc, exc_info=True,
            )
        log.info("[%s] sleeping %ds until next poll.", label, POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)


def main() -> None:
    if OUTPUT_FORMAT not in _VALID_FORMATS:
        log.error(
            "main: OUTPUT_FORMAT=%r is invalid. Must be one of: %s. Exiting.",
            OUTPUT_FORMAT, sorted(_VALID_FORMATS),
        )
        sys.exit(1)

    log.info(
        "Cortex XDR poller starting — format=%s interval=%ds | "
        "alerts=%s | incidents=%s | mgmt_audit=%s | agent_audit=%s | "
        "ops=%s (info=cortex_info.log error=cortex_error.log) | state=%s",
        OUTPUT_FORMAT.upper(), POLL_INTERVAL,
        LOG_DIR, INCIDENTS_LOG_DIR, AUDIT_MGMT_LOG_DIR,
        AUDIT_AGENT_LOG_DIR, OPS_LOG_DIR, STATE_FILE,
    )

    state = load_state()

    for _, state_key, label in _STREAMS:
        if state.get(state_key):
            log.info(
                "%s: resuming from last seen timestamp %s.",
                label, epoch_ms_to_iso(state[state_key]),
            )
        else:
            log.info(
                "%s: no prior state found — lookback will apply on first poll.",
                label,
            )

    log.info("Starting %d independent stream threads.", len(_STREAMS))

    threads = []
    for poll_fn, _, label in _STREAMS:
        t = threading.Thread(
            target  = _stream_loop,
            args    = (poll_fn, state, label),
            name    = label,
            daemon  = True,   # threads exit automatically when main exits
        )
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log.info("Cortex XDR poller stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
