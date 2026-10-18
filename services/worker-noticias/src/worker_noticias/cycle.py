"""Periodic loop of the news worker (ADR 0007): own loop, no Celery.

`run_cycle` reads every feed once; `run_forever` repeats it every interval.

Isolation: "source" is one feed. Each feed runs in its own error handling, so a
feed that fails, times out or is forbidden never stops the others (acceptance
criterion 4). Per feed, in order: the robots.txt decision (one `RobotsCache`
per cycle, so one download per host), then download, parse and save. A feed
whose robots.txt forbids it is `disabled` and its URL is never requested. If
the download was redirected (same host only), the final path is checked with
the same cache; a forbidden target discards the body (`disabled`).

Logs name only the source id, the status, counts and a fixed reason code, never
titles, summaries, bodies, robots.txt text, URLs with a query string or the
message of an exception (it may carry data). An unexpected exception is logged
with its class name only.

Timing: the interval is measured with `time.monotonic` from the start of each
cycle, so the cycles do not drift and a wall-clock change does not matter. If a
cycle takes longer than the interval, the next one starts immediately and the
overrun is logged. The retention purge runs once per cycle, after the feeds,
and its failure is isolated too. A stop request ends the loop after the current
cycle (the cycle itself can last up to a few minutes: each download is bounded
by the 30 s deadline of `fetch`).

Run exactly ONE replica (ADR 0007): there is no distributed lock. A second
replica would not duplicate rows (the link is unique) but would double the
traffic to the outlets.
"""

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from worker_noticias import feeds, fetch, robots
from worker_noticias.feeds import FeedError
from worker_noticias.store import ConfigError, SaveResult, StoreError

module_logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_MINUTES = 30
MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 1440
INTERVAL_MESSAGE = (
    "WORKER_NOTICIAS_INTERVAL_MINUTES must be an integer from "
    f"{MIN_INTERVAL_MINUTES} to {MAX_INTERVAL_MINUTES}"
)

OK = "ok"
DISABLED = "disabled"
FAILED = "failed"


@dataclass(frozen=True)
class SourceReport:
    """Outcome of one feed. `reason` is a fixed code, None when `ok`."""

    source_id: str
    status: str
    read: int
    new: int
    skipped: int
    reason: str | None


@dataclass(frozen=True)
class CycleReport:
    sources: tuple[SourceReport, ...]

    @property
    def ok(self) -> bool:
        """True when no feed failed (a feed disabled by robots is a decision)."""
        return all(r.status != FAILED for r in self.sources)


def interval() -> timedelta:
    """Interval from WORKER_NOTICIAS_INTERVAL_MINUTES (5 to 1440, default 30)."""
    raw = os.environ.get("WORKER_NOTICIAS_INTERVAL_MINUTES")
    if raw is None:
        return timedelta(minutes=DEFAULT_INTERVAL_MINUTES)
    raw = raw.strip()
    # isascii: int() also accepts digits of other scripts.
    if not (raw.isascii() and raw.isdigit()):
        raise ConfigError(INTERVAL_MESSAGE)
    minutes = int(raw)
    if not MIN_INTERVAL_MINUTES <= minutes <= MAX_INTERVAL_MINUTES:
        raise ConfigError(INTERVAL_MESSAGE)
    return timedelta(minutes=minutes)


def _read_source(source, fetcher, saver, cache) -> SourceReport:
    """Robots, download, parse, save for one feed; failures propagate."""
    decision = cache.check(source)
    if not decision.allowed:
        return SourceReport(source.id, DISABLED, 0, 0, 0, decision.reason)
    result = fetcher(source.url)
    if result.final_url != source.url:
        # A same-host redirect lands on another path: robots.txt rules apply
        # to it too. The body is dropped unparsed and unsaved.
        moved = cache.check(source, result.final_url)
        if not moved.allowed:
            return SourceReport(source.id, DISABLED, 0, 0, 0, moved.reason)
    parsed = feeds.parse_feed(source, result.body)
    saved: SaveResult = saver(parsed.items)
    return SourceReport(
        source.id,
        OK,
        len(parsed.items),
        saved.new,
        parsed.skipped + saved.skipped,
        None,
    )


def _failed(source_id: str, reason: str) -> SourceReport:
    return SourceReport(source_id, FAILED, 0, 0, 0, reason)


def _read_isolated(source, fetcher, saver, cache, logger) -> SourceReport:
    try:
        return _read_source(source, fetcher, saver, cache)
    except fetch.FetchError as exc:
        return _failed(source.id, f"fetch_{exc.reason}")
    except FeedError as exc:
        return _failed(source.id, f"feed_{exc.reason}")
    except StoreError:
        return _failed(source.id, "store_error")
    except Exception as exc:
        # Last resort: the class name only, the message may carry data.
        logger.error("source %s: unexpected %s", source.id, type(exc).__name__)
        return _failed(source.id, "unexpected_error")


def _log_report(report: SourceReport, logger) -> None:
    level = logging.WARNING if report.status == FAILED else logging.INFO
    logger.log(
        level,
        "source %s: %s read=%d new=%d skipped=%d reason=%s",
        report.source_id,
        report.status,
        report.read,
        report.new,
        report.skipped,
        report.reason or "-",
    )


def run_cycle(
    sources=feeds.SOURCES,
    *,
    fetcher: Callable[[str], fetch.FetchResult] = fetch.fetch,
    saver: Callable[[list], SaveResult],
    robots_cache_factory: Callable[[], object] | None = None,
    clock: Callable[[], float] = time.monotonic,
    logger: logging.Logger = module_logger,
) -> CycleReport:
    """Read every feed once; one feed failing never stops the others."""
    started = clock()
    cache = (robots_cache_factory or (lambda: robots.RobotsCache(fetcher)))()
    reports = []
    for source in sources:
        report = _read_isolated(source, fetcher, saver, cache, logger)
        _log_report(report, logger)
        reports.append(report)
    result = CycleReport(tuple(reports))
    failed = sum(r.status == FAILED for r in reports)
    logger.info(
        "cycle done: %d feed(s), %d failed, %.1f s",
        len(reports),
        failed,
        clock() - started,
    )
    return result


def _isolated(name: str, action: Callable[[], object], logger) -> None:
    """Run a step of the loop; a failure is logged (class name only) and kept."""
    try:
        action()
    except Exception as exc:
        logger.error("%s failed: %s", name, type(exc).__name__)


def run_forever(
    interval: timedelta,
    *,
    cycle: Callable[[], CycleReport],
    purge: Callable[[], object] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], object] = time.sleep,
    stop: Callable[[], bool] = lambda: False,
    logger: logging.Logger = module_logger,
) -> None:
    """Run `cycle` (then `purge`) every `interval` until `stop()` is true.

    `stop` is checked after each cycle and after each sleep, never in the
    middle of a cycle. Pass an event's `wait` as `sleep` to wake up on a stop.
    """
    seconds = interval.total_seconds()
    while True:
        started = clock()
        _isolated("cycle", cycle, logger)
        if purge is not None:
            _isolated("purge", purge, logger)
        if stop():
            return
        remaining = seconds - (clock() - started)
        if remaining > 0:
            sleep(remaining)
        else:
            logger.warning("cycle overran the interval by %.1f s", -remaining)
        if stop():
            return
