from api_base import fetch_all
from config import FQDN


def fetch_agent_audits(since_ts: int, page_callback=None) -> list[dict] | None:
    """
    Fetch all Cortex XDR agent audit reports with timestamp >= since_ts.

    Endpoint : POST /public_api/v1/audits/agents_reports
    Reply key: data  (audit endpoints return results under 'data', not 'alerts')
    Time field: timestamp  (audit endpoints use 'timestamp', not 'creation_time')
    """
    return fetch_all(
        url           = f"{FQDN}/public_api/v1/audits/agents_reports",
        since_ts      = since_ts,
        reply_key     = "data",
        label         = "agent_audits",
        time_field    = "timestamp",
        page_callback = page_callback,
    )
