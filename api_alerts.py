from api_base import fetch_all
from config import FQDN


def fetch_alerts(since_ts: int, page_callback=None) -> list[dict] | None:
    """
    Fetch all Cortex XDR alerts with creation_time >= since_ts.

    Endpoint  : POST /public_api/v1/alerts/get_alerts
    Reply key : alerts
    Time field: creation_time  (API filter/sort field — maps to detection_timestamp in response)
    Count key : total_count
    """
    return fetch_all(
        url           = f"{FQDN}/public_api/v1/alerts/get_alerts",
        since_ts      = since_ts,
        reply_key     = "alerts",
        label         = "alerts",
        time_field    = "creation_time",
        page_callback = page_callback,
    )
