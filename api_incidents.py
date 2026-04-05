from api_base import fetch_all
from config import FQDN


def fetch_incidents(since_ts: int, page_callback=None) -> list[dict] | None:
    """
    Fetch all Cortex XDR incidents with modification_time >= since_ts.

    Endpoint  : POST /public_api/v1/incidents/get_incidents
    Reply key : incidents
    Time field: modification_time  (epoch ms)
    Count key : total_count

    Filters by modification_time so that updates to existing incidents
    (status changes, severity escalations, resolve comments) are captured
    on subsequent polls.
    """
    return fetch_all(
        url           = f"{FQDN}/public_api/v1/incidents/get_incidents",
        since_ts      = since_ts,
        reply_key     = "incidents",
        label         = "incidents",
        time_field    = "modification_time",
        page_callback = page_callback,
    )
