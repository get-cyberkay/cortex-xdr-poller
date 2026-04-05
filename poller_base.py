from datetime import datetime, timezone, timedelta
import logging
import queue
import threading

import config as _config
from formatters import format_record
from logging_setup import log
from state import save_state
from syslog_handler import send_syslog


def compute_lookback_ts(label: str = "") -> int:
    """
    Compute the epoch-ms lower bound for a stream's very first run.

    Priority: LOOKBACK_HOURS > LOOKBACK_DAYS > default 24 h.
    Accepts floats (e.g. LOOKBACK_HOURS=1.5).
    Returns epoch MILLISECONDS — Cortex XDR timestamps are consistently
    in milliseconds regardless of the spec ambiguity.
    Logs ERROR when a configured value cannot be parsed as a float and
    falls through to the next option rather than crashing.
    """
    now = datetime.now(tz=timezone.utc)

    if _config.LOOKBACK_HOURS:
        try:
            delta = timedelta(hours=float(_config.LOOKBACK_HOURS))
            log.info(
                "compute_lookback_ts [%s]: first run — looking back %s hour(s).",
                label, _config.LOOKBACK_HOURS,
            )
            return int((now - delta).timestamp() * 1000)
        except ValueError:
            log.error(
                "compute_lookback_ts [%s]: LOOKBACK_HOURS=%r is not a valid number. "
                "Falling through to LOOKBACK_DAYS.",
                label, _config.LOOKBACK_HOURS,
            )

    if _config.LOOKBACK_DAYS:
        try:
            delta = timedelta(days=float(_config.LOOKBACK_DAYS))
            log.info(
                "compute_lookback_ts [%s]: first run — looking back %s day(s).",
                label, _config.LOOKBACK_DAYS,
            )
            return int((now - delta).timestamp() * 1000)
        except ValueError:
            log.error(
                "compute_lookback_ts [%s]: LOOKBACK_DAYS=%r is not a valid number. "
                "Defaulting to 24 hours.",
                label, _config.LOOKBACK_DAYS,
            )

    log.info(
        "compute_lookback_ts [%s]: no lookback configured — defaulting to 24 hours.",
        label,
    )
    return int((now - timedelta(hours=24)).timestamp() * 1000)


def poll_stream(
    state: dict,
    state_key: str,
    fetch_fn,
    stream: str,
    output_logger,
    ts_field: str,
    label: str,
    syslog_app_name: str,
) -> dict:
    """
    Execute one poll cycle for a single data stream.

    Records are written to file and forwarded to syslog immediately as each
    API page arrives — not after all pages have been collected.  State is
    advanced after every page so progress is preserved even when a later page
    fails.

    INFO logs on: poll start, per-page progress (via fetch_all), completion.
    ERROR logs on: format failure per record, file write failure, unexpected
                   syslog error.  Records that fail formatting are skipped.

    None from fetch_fn → partial or full failure already logged; state reflects
                         whatever pages were successfully processed.
    []   from fetch_fn → clean empty poll; logged as "no new records".
    """
    since_ts = state.get(state_key) or compute_lookback_ts(label)

    log.info(
        "poll_stream [%s]: starting poll — since %s.",
        label, _epoch_to_iso_safe(since_ts),
    )

    file_on = bool(
        output_logger.handlers
        and not isinstance(output_logger.handlers[0], logging.NullHandler)
    )

    # Shared counters written only by the processor thread.
    ctx = {"max_ts": since_ts, "written": 0, "skipped": 0}

    # Unbounded so on_page() never blocks — the fetch loop proceeds to the
    # next HTTP request the instant a page is enqueued.
    page_queue: queue.Queue = queue.Queue()

    def on_page(page: list[dict]) -> None:
        """
        Called by fetch_all the moment each page arrives.
        Just enqueues and returns — zero blocking, fetch loop continues
        immediately to the next API request.
        """
        page_queue.put(page)

    def _record_processor() -> None:
        """
        Drains page_queue concurrently with the fetch loop.

        For each record:
          1. format_record()             — CPU work, done here
          2. output_logger.info()        — enqueues to QueueHandler (async)
          3. send_syslog()               — enqueues to syslog worker (async)

        State cursor is advanced after every page so progress survives a
        mid-fetch failure on later pages.
        """
        while True:
            page = page_queue.get()
            if page is None:        # sentinel — fetch complete or failed
                break

            for record in page:
                # --- format ---
                try:
                    formatted = format_record(record, stream)
                except Exception as exc:
                    log.error(
                        "poll_stream [%s]: format_record failed "
                        "(ts_field=%r value=%r format=%s): %s. Record skipped.",
                        label, ts_field, record.get(ts_field),
                        _config.OUTPUT_FORMAT, exc,
                    )
                    ctx["skipped"] += 1
                    continue

                # --- file (async QueueHandler) ---
                try:
                    output_logger.info(formatted)
                except Exception as exc:
                    log.error(
                        "poll_stream [%s]: file write failed "
                        "(ts_field=%r value=%r): %s.",
                        label, ts_field, record.get(ts_field), exc,
                    )

                # --- syslog (async worker queue) ---
                try:
                    send_syslog(formatted, syslog_app_name)
                except Exception as exc:
                    log.error(
                        "poll_stream [%s]: send_syslog raised unexpectedly "
                        "(ts_field=%r value=%r): %s.",
                        label, ts_field, record.get(ts_field), exc,
                    )

                ts = record.get(ts_field)
                if ts and isinstance(ts, (int, float)) and ts > ctx["max_ts"]:
                    ctx["max_ts"] = int(ts)
                ctx["written"] += 1

            # Save state after each page — survives mid-fetch failures.
            if ctx["max_ts"] > since_ts:
                state[state_key] = ctx["max_ts"]
                save_state(state)

    # Start the processor before fetching so it is ready to consume immediately.
    processor = threading.Thread(
        target=_record_processor,
        name=f"processor-{label}",
        daemon=True,
    )
    processor.start()

    # API fetch runs in this thread; on_page() is a non-blocking enqueue.
    # Processor and fetch loop run concurrently — record formatting and
    # file/syslog enqueuing overlap with network I/O for subsequent pages.
    result = fetch_fn(since_ts, page_callback=on_page)

    # Send sentinel and wait for the processor to finish all queued pages.
    page_queue.put(None)
    processor.join()

    if result is None:
        if ctx["written"] > 0:
            log.info(
                "poll_stream [%s]: partial cycle — %d record(s) written before "
                "fetch failure [format=%s file=%s syslog=%s].",
                label, ctx["written"],
                _config.OUTPUT_FORMAT.upper(),
                "on" if file_on else "off",
                "on" if _config.ENABLE_SYSLOG else "off",
            )
        return state

    if ctx["written"] == 0:
        log.info("poll_stream [%s]: no new records.", label)
        return state

    log.info(
        "poll_stream [%s]: cycle complete — %d record(s) written, "
        "%d skipped [format=%s file=%s syslog=%s].",
        label, ctx["written"], ctx["skipped"],
        _config.OUTPUT_FORMAT.upper(),
        "on" if file_on else "off",
        "on" if _config.ENABLE_SYSLOG else "off",
    )
    return state


def _epoch_to_iso_safe(ts: int) -> str:
    """Convert epoch timestamp (seconds or ms) to ISO string. Never raises."""
    try:
        from leef import epoch_to_iso
        return epoch_to_iso(ts)
    except Exception:
        return str(ts)
