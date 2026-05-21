import hashlib
import secrets
import string
import time
import requests

import config as _config
from config import PAGE_SIZE, SSL_VERIFY
from leef import epoch_ms_to_iso
from logging_setup import log


# Warn once at import time if SSL verification is disabled.
if not SSL_VERIFY:
    log.warning(
        "SSL_VERIFY=false: TLS certificate verification is DISABLED. "
        "Do not use this setting in production."
    )

_NONCE_ALPHABET = string.ascii_letters + string.digits


def build_headers() -> dict[str, str]:
    """
    Build the request headers for a single Cortex XDR API call.

    Standard auth  (API_AUTH_TYPE=standard):
        Authorization: <api_key>
        x-xdr-auth-id: <api_key_id>

    Advanced auth  (API_AUTH_TYPE=advanced):
        Authorization: SHA-256(api_key + nonce + timestamp_ms)
        x-xdr-auth-id: <api_key_id>
        x-xdr-nonce:   <64-char random string>
        x-xdr-timestamp: <epoch milliseconds>

    Advanced headers are generated fresh on every call because the nonce and
    timestamp must be unique per request.
    """
    headers: dict[str, str] = {
        "Accept":         "application/json",
        "Content-Type":   "application/json",
        "x-xdr-auth-id":  str(_config.API_KEY_ID),
    }

    if _config.API_AUTH_TYPE == "advanced":
        nonce        = "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(64))
        timestamp_ms = str(int(time.time() * 1000))
        auth_string  = _config.API_KEY + nonce + timestamp_ms
        auth_hash    = hashlib.sha256(auth_string.encode("utf-8")).hexdigest()
        headers["x-xdr-nonce"]     = nonce
        headers["x-xdr-timestamp"] = timestamp_ms
        headers["Authorization"]   = auth_hash
    else:
        headers["Authorization"] = _config.API_KEY

    return headers


_proxies_cache: dict | None = None
_proxies_resolved: bool = False


def _build_proxies() -> dict | None:
    """
    Return a requests-compatible proxies dict when USE_PROXY=true, or None.
    Result is cached after the first call — config is read only once.
    Logs ERROR when USE_PROXY=true but no proxy URLs are configured.
    """
    global _proxies_cache, _proxies_resolved
    if _proxies_resolved:
        return _proxies_cache

    if not _config.USE_PROXY:
        _proxies_resolved = True
        return None

    if not _config.PROXY_HTTP and not _config.PROXY_HTTPS:
        log.error(
            "_build_proxies: USE_PROXY=true but neither PROXY_HTTP nor "
            "PROXY_HTTPS is set. No proxy will be applied."
        )
        _proxies_resolved = True
        return None

    proxies: dict[str, str] = {}
    if _config.PROXY_HTTP:
        proxies["http"] = _config.PROXY_HTTP
    if _config.PROXY_HTTPS:
        proxies["https"] = _config.PROXY_HTTPS

    log.info(
        "Proxy enabled. http=%s https=%s",
        _config.PROXY_HTTP or "(none)", _config.PROXY_HTTPS or "(none)",
    )
    _proxies_cache = proxies
    _proxies_resolved = True
    return _proxies_cache


def _fetch_page_once(
    url: str,
    since_ts: int,
    search_from: int,
    reply_key: str,
    time_field: str,
    total_count_key: str = "total_count",
    extra_payload: dict | None = None,
) -> tuple[list[dict], int] | tuple[None, None]:
    """
    Attempt a single HTTP request for one page of results.

    reply_key       — key inside reply{} holding the result list.
                      alerts/incidents → "alerts"/"incidents"
                      XSIAM issues     → "issues"
                      XSIAM cases      → "DATA"  (uppercase)
    total_count_key — key inside reply{} holding the total count.
                      Most endpoints  → "total_count"
                      XSIAM cases     → "TOTAL_COUNT" (uppercase)
    extra_payload   — optional dict merged into request_data (e.g.
                      {"include_fields": ["normalized_fields"]} for issues)

    Returns (records_list, total_count) on success, (None, None) on error.
    """
    request_data: dict = {
        "filters": [
            {
                "field":    time_field,
                "operator": "gte",
                "value":    since_ts,
            }
        ],
        "sort": {
            "field":   time_field,
            "keyword": "asc",
        },
        "search_from": search_from,
        "search_to":   search_from + PAGE_SIZE,
    }

    if extra_payload:
        request_data.update(extra_payload)

    payload = {"request_data": request_data}

    try:
        response = requests.post(
            url,
            headers = build_headers(),
            json    = payload,
            timeout = _config.REQUEST_TIMEOUT_SECONDS,
            proxies = _build_proxies(),
            verify  = SSL_VERIFY,
        )
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.SSLError as exc:
        log.error(
            "_fetch_page [%s offset=%d]: SSL certificate verification failed. "
            "If using a TLS-inspecting proxy, set SSL_VERIFY=false. "
            "Error: %s",
            url, search_from, exc,
        )
        return None, None

    except requests.exceptions.ConnectionError as exc:
        log.error(
            "_fetch_page [%s offset=%d]: connection failed. "
            "Verify FQDN, network access, firewall rules, and proxy settings. "
            "Error: %s",
            url, search_from, exc,
        )
        return None, None

    except requests.exceptions.Timeout:
        log.error(
            "_fetch_page [%s offset=%d]: request timed out after %ds. "
            "If this recurs, increase REQUEST_TIMEOUT_SECONDS in .env.",
            url, search_from, _config.REQUEST_TIMEOUT_SECONDS,
        )
        return None, None

    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        log.error(
            "_fetch_page [%s offset=%d]: HTTP %s error: %s",
            url, search_from, status, exc,
        )
        return None, None

    except requests.RequestException as exc:
        log.error(
            "_fetch_page [%s offset=%d]: unexpected request error: %s",
            url, search_from, exc,
        )
        return None, None

    except ValueError as exc:
        log.error(
            "_fetch_page [%s offset=%d]: failed to decode JSON response: %s",
            url, search_from, exc,
        )
        return None, None

    reply = data.get("reply", {})

    # XSIAM case/issue endpoints return errors under "error" at root level,
    # not inside reply{}. Handle both patterns.
    if "error" in data and not reply:
        log.error(
            "_fetch_page [%s offset=%d]: API returned error: %r",
            url, search_from, data["error"],
        )
        return None, None

    if "err_code" in reply or "err_msg" in reply:
        log.error(
            "_fetch_page [%s offset=%d]: API returned an error — "
            "err_code=%r err_msg=%r err_extra=%r",
            url, search_from,
            reply.get("err_code"), reply.get("err_msg"), reply.get("err_extra"),
        )
        return None, None

    records     = reply.get(reply_key, [])
    total_count = int(reply.get(total_count_key, 0))
    return records, total_count


def _fetch_page(
    url: str,
    since_ts: int,
    search_from: int,
    reply_key: str,
    time_field: str,
    total_count_key: str = "total_count",
    extra_payload: dict | None = None,
) -> tuple[list[dict], int] | tuple[None, None]:
    """
    Fetch one page with retry + exponential backoff.

    Retries up to REQUEST_MAX_RETRIES times on failure.
    Backoff: attempt 1 → immediate, attempt 2 → 1s, attempt 3 → 2s, etc.
    """
    max_attempts = max(1, _config.REQUEST_MAX_RETRIES)

    for attempt in range(1, max_attempts + 1):
        page, total_count = _fetch_page_once(
            url             = url,
            since_ts        = since_ts,
            search_from     = search_from,
            reply_key       = reply_key,
            time_field      = time_field,
            total_count_key = total_count_key,
            extra_payload   = extra_payload,
        )

        if page is not None:
            return page, total_count

        if attempt == max_attempts:
            log.error(
                "_fetch_page [%s offset=%d]: all %d attempt(s) failed. Giving up.",
                url, search_from, max_attempts,
            )
            return None, None

        backoff = 2 ** (attempt - 1)
        log.warning(
            "_fetch_page [%s offset=%d]: attempt %d/%d failed — "
            "retrying in %ds.",
            url, search_from, attempt, max_attempts, backoff,
        )
        time.sleep(backoff)

    return None, None


def fetch_all(
    url: str,
    since_ts: int,
    reply_key: str,
    label: str,
    time_field: str,
    total_count_key: str = "total_count",
    extra_payload: dict | None = None,
    page_callback=None,
) -> list[dict] | None:
    """
    Paginate through all results from a Cortex XDR / XSIAM list endpoint.

    page_callback — optional callable(page: list[dict]) -> None.
        Called immediately after each page arrives, before the next request
        is issued.  Use this to write/forward records in real time rather than
        waiting for the entire result set to be collected.

    Returns the full list on success, or None if any page fails after retries.
    None vs [] is intentional — callers must NOT update state on None.
    When page_callback is provided and a mid-fetch failure occurs, records
    already delivered to the callback are NOT rolled back — the caller is
    responsible for advancing state based on what was processed.
    """
    all_records: list[dict] = []
    search_from = 0
    total_count = 0

    while True:
        page, total_count = _fetch_page(
            url             = url,
            since_ts        = since_ts,
            search_from     = search_from,
            reply_key       = reply_key,
            time_field      = time_field,
            total_count_key = total_count_key,
            extra_payload   = extra_payload,
        )

        if page is None:
            log.error(
                "fetch_all [%s]: pagination aborted at offset %d. "
                "%d record(s) already delivered to callback this cycle. "
                "Will resume from last saved state on next poll interval.",
                label, search_from, len(all_records),
            )
            return None

        # Deliver to the caller immediately — before fetching the next page.
        if page_callback is not None and page:
            page_callback(page)

        all_records.extend(page)

        if total_count >= 9999 and search_from == 0:
            log.warning(
                "fetch_all [%s]: total_count=%d (>= 9999) — API result set is capped. "
                "Reduce LOOKBACK_DAYS / LOOKBACK_HOURS or POLL_INTERVAL_SECONDS "
                "to avoid missing records between polls.",
                label, total_count,
            )

        log.info(
            "fetch_all [%s]: page fetched — offset=%d, got=%d, total_count=%d.",
            label, search_from, len(page), total_count,
        )

        search_from += PAGE_SIZE

        if search_from >= total_count or len(page) == 0:
            break

    log.info(
        "fetch_all [%s]: completed — %d record(s) fetched (total_count=%d) since %s.",
        label, len(all_records), total_count, epoch_ms_to_iso(since_ts),
    )
    return all_records
