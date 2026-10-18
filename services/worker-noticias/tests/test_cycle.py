"""Tests for the periodic loop (ADR 0007): isolation, robots, logs, timing.

Nothing here touches the network or sleeps: the fetcher, the saver, the clock
and the sleep are fakes.
"""

import logging
from datetime import timedelta

import pytest

from worker_noticias import cycle, feeds
from worker_noticias.fetch import FetchError, FetchResult
from worker_noticias.store import ConfigError, SaveResult, StoreError

BY_ID = {source.id: source for source in feeds.SOURCES}
ALL_IDS = [source.id for source in feeds.SOURCES]
# Content that must never reach a log line.
SENTINEL_TITLE = "SENTINEL-TITLE"
SENTINEL_SUMMARY = "SENTINEL-SUMMARY"
SENTINEL_ROBOTS = "SENTINEL-ROBOTS-RULE"
SENTINEL_MESSAGE = "SENTINEL-EXCEPTION-MESSAGE"


def rss_body(source) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><item>'
        f"<title>{SENTINEL_TITLE}</title><link>{source.url.split('?')[0]}/n1</link>"
        "<pubDate>Thu, 15 Oct 2026 10:00:00 -0500</pubDate>"
        f"<description>{SENTINEL_SUMMARY}</description></item>"
        "<item><title>no link</title></item></channel></rss>"
    ).encode()


def sitemap_body(source) -> bytes:
    host = source.url.split("/")[2]
    return (
        '<?xml version="1.0"?><urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:news="http://www.google.com/schemas/sitemap-news/0.9"><url>'
        f"<loc>https://{host}/n1</loc><news:news><news:publication>"
        "<news:name>X</news:name><news:language>es</news:language>"
        "</news:publication><news:publication_date>2026-10-15T09:30:00-05:00"
        f"</news:publication_date><news:title>{SENTINEL_TITLE}</news:title>"
        "</news:news></url></urlset>"
    ).encode()


def good_body(source) -> bytes:
    return rss_body(source) if source.kind == "rss" else sitemap_body(source)


class FakeFetcher:
    """Serves each feed URL from `overrides` or a good body; robots from `robots`."""

    def __init__(self, overrides=None, robots_txt="User-agent: *\nAllow: /\n"):
        self.overrides = overrides or {}
        self.robots_txt = robots_txt
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        if url.endswith("/robots.txt"):
            outcome = self.robots_txt
            if isinstance(outcome, Exception):
                raise outcome
            return FetchResult(200, outcome.encode(), url)
        source = next(s for s in feeds.SOURCES if s.url == url)
        outcome = self.overrides.get(source.id, good_body(source))
        if isinstance(outcome, Exception):
            raise outcome
        return FetchResult(200, outcome, url)

    def feed_requests(self):
        return [u for u in self.urls if not u.endswith("/robots.txt")]


class RecordingSaver:
    def __init__(self, error_for=None):
        self.calls = []
        self.error_for = error_for or {}

    def __call__(self, items):
        self.calls.append(list(items))
        source_id = items[0].source_id if items else None
        if source_id in self.error_for:
            raise self.error_for[source_id]
        return SaveResult(new=len(items), skipped=0)


def run(fetcher, saver=None, **kwargs):
    return cycle.run_cycle(
        feeds.SOURCES, fetcher=fetcher, saver=saver or RecordingSaver(), **kwargs
    )


def by_id(report):
    return {r.source_id: r for r in report.sources}


# --- run_cycle ----------------------------------------------------------------


def test_a_clean_cycle_reads_and_saves_every_feed_and_reports_counts():
    saver = RecordingSaver()
    report = run(FakeFetcher(), saver)
    assert [r.source_id for r in report.sources] == ALL_IDS
    assert report.ok
    for r in report.sources:
        assert (r.status, r.read, r.new, r.reason) == ("ok", 1, 1, None)
    assert len(saver.calls) == len(ALL_IDS)


def test_skipped_counts_the_parser_and_the_saver_skips():
    def saver(items):
        return SaveResult(new=0, skipped=2)

    report = run(FakeFetcher(), saver)
    r = by_id(report)["semana-rss"]
    # The RSS fixture has one invalid entry (no link): 1 parser skip + 2 saver skips.
    assert (r.read, r.new, r.skipped) == (1, 0, 3)


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (FetchError("timeout"), "fetch_timeout"),
        (FetchError("http_status", 503), "fetch_http_status"),
        (b"<rss", "feed_malformed"),
        (b"<html/>", "feed_unknown_format"),
        (RuntimeError(SENTINEL_MESSAGE), "unexpected_error"),
    ],
)
def test_a_failing_feed_is_isolated_and_the_others_are_saved(failure, reason, caplog):
    saver = RecordingSaver()
    fetcher = FakeFetcher({"semana-rss": failure})
    with caplog.at_level(logging.DEBUG):
        report = run(fetcher, saver)
    rows = by_id(report)
    assert (rows["semana-rss"].status, rows["semana-rss"].reason) == ("failed", reason)
    assert (rows["semana-rss"].read, rows["semana-rss"].new) == (0, 0)
    assert [r.status for r in report.sources if r.source_id != "semana-rss"] == [
        "ok"
    ] * 5
    assert len(saver.calls) == 5
    assert not report.ok
    assert "semana-rss" in caplog.text
    assert SENTINEL_MESSAGE not in caplog.text


def test_three_different_failures_do_not_stop_the_remaining_feeds():
    fetcher = FakeFetcher(
        {
            "rcn-rss": FetchError("dns"),
            "rcn-sitemap": b"<rss",
            "semana-rss": RuntimeError("boom"),
        }
    )
    saver = RecordingSaver()
    report = run(fetcher, saver)
    assert [r.status for r in report.sources] == ["failed"] * 3 + ["ok"] * 3
    assert {c[0].source_id for c in saver.calls} == {
        "caracol-sitemap",
        "blu-radio-sitemap",
        "citytv-sitemap",
    }


def test_a_store_error_fails_only_that_feed():
    saver = RecordingSaver(error_for={"caracol-sitemap": StoreError("could not")})
    report = run(FakeFetcher(), saver)
    assert (by_id(report)["caracol-sitemap"].status,) == ("failed",)
    assert by_id(report)["caracol-sitemap"].reason == "store_error"
    assert by_id(report)["citytv-sitemap"].status == "ok"


def test_an_unexpected_robots_error_fails_only_that_feed():
    class Boom:
        def check(self, source):
            if source.id == "rcn-rss":
                raise RuntimeError("robots broke")
            return cycle.robots.RobotsDecision(True, "allowed")

    report = run(FakeFetcher(), robots_cache_factory=Boom)
    assert by_id(report)["rcn-rss"].reason == "unexpected_error"
    assert by_id(report)["rcn-sitemap"].status == "ok"


def test_a_feed_forbidden_by_robots_is_disabled_and_never_requested():
    robots_txt = f"# {SENTINEL_ROBOTS}\nUser-agent: *\nDisallow: /\n"
    fetcher = FakeFetcher(robots_txt=robots_txt)
    saver = RecordingSaver()
    report = run(fetcher, saver)
    assert all(r.status == "disabled" for r in report.sources)
    assert all(r.reason == "disallowed" for r in report.sources)
    assert fetcher.feed_requests() == []
    assert saver.calls == []
    assert report.ok  # a disabled feed is a decision, not a failure


def test_robots_unavailable_disables_the_host_without_requesting_the_feed():
    fetcher = FakeFetcher(robots_txt=FetchError("http_status", 503))
    report = run(fetcher)
    assert {r.reason for r in report.sources} == {"unavailable"}
    assert fetcher.feed_requests() == []


def test_one_robots_download_per_host_per_cycle():
    fetcher = FakeFetcher()
    run(fetcher)
    robots_urls = [u for u in fetcher.urls if u.endswith("/robots.txt")]
    assert robots_urls.count("https://www.noticiasrcn.com/robots.txt") == 1
    assert len(robots_urls) == len(set(robots_urls)) == 5
    run(fetcher)  # a new cycle downloads again
    robots_urls = [u for u in fetcher.urls if u.endswith("/robots.txt")]
    assert robots_urls.count("https://www.noticiasrcn.com/robots.txt") == 2


def test_the_feed_is_read_after_the_robots_decision():
    fetcher = FakeFetcher()
    run(fetcher)
    assert fetcher.urls.index(BY_ID["rcn-rss"].url) > fetcher.urls.index(
        "https://www.noticiasrcn.com/robots.txt"
    )


def test_logs_carry_no_content_no_query_string_and_no_exception_message(caplog):
    fetcher = FakeFetcher(
        {"rcn-sitemap": RuntimeError(f"{SENTINEL_MESSAGE} {SENTINEL_TITLE}")},
        robots_txt=f"# {SENTINEL_ROBOTS}\nUser-agent: *\nDisallow: /nada\n",
    )
    with caplog.at_level(logging.DEBUG):
        run(fetcher)
    for sentinel in (
        SENTINEL_TITLE,
        SENTINEL_SUMMARY,
        SENTINEL_ROBOTS,
        SENTINEL_MESSAGE,
        "outputType",
        "http",
    ):
        assert sentinel not in caplog.text
    assert "RuntimeError" in caplog.text
    assert "rcn-sitemap" in caplog.text


# --- run_forever --------------------------------------------------------------


class FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def make_loop(duration, cycles, purge=None, stop_after=None, **extra):
    """Run the loop with cycles taking `duration` seconds (a list or a number)."""
    fake = FakeTime()
    calls = []
    durations = list(duration) if isinstance(duration, list) else None

    def one_cycle():
        calls.append(fake.now)
        fake.now += durations[len(calls) - 1] if durations else duration
        return cycle.CycleReport(())

    stop_after = cycles if stop_after is None else stop_after
    cycle.run_forever(
        timedelta(seconds=300),
        cycle=one_cycle,
        purge=purge,
        clock=fake.clock,
        sleep=fake.sleep,
        stop=lambda: len(calls) >= stop_after,
        **extra,
    )
    return fake, calls


def test_the_loop_sleeps_the_rest_of_the_interval():
    fake, calls = make_loop(duration=100, cycles=3)
    assert fake.sleeps == [200, 200]  # none after the last cycle
    assert calls == [1000.0, 1300.0, 1600.0]  # no drift: every 300 s


def test_an_overrunning_cycle_is_followed_immediately_and_logged(caplog):
    with caplog.at_level(logging.INFO):
        fake, calls = make_loop(duration=[400, 100, 100], cycles=3)
    assert calls == [1000.0, 1400.0, 1700.0]
    assert fake.sleeps == [200]  # no sleep after the 400 s cycle
    assert "overran" in caplog.text


def test_the_stop_flag_ends_the_loop_after_the_current_cycle_without_sleeping():
    fake, calls = make_loop(duration=10, cycles=1)
    assert len(calls) == 1
    assert fake.sleeps == []


def test_a_stop_during_the_sleep_does_not_start_another_cycle():
    fake = FakeTime()
    stopped = []

    def sleep(seconds):
        fake.sleep(seconds)
        stopped.append(True)  # the signal arrives while waiting

    calls = []
    cycle.run_forever(
        timedelta(seconds=300),
        cycle=lambda: calls.append(1) or cycle.CycleReport(()),
        clock=fake.clock,
        sleep=sleep,
        stop=lambda: bool(stopped),
    )
    assert len(calls) == 1


def test_the_purge_runs_once_per_cycle_after_the_feeds():
    order = []
    fake = FakeTime()
    cycle.run_forever(
        timedelta(seconds=300),
        cycle=lambda: order.append("cycle") or cycle.CycleReport(()),
        purge=lambda: order.append("purge"),
        clock=fake.clock,
        sleep=fake.sleep,
        stop=lambda: order.count("cycle") >= 2,
    )
    assert order == ["cycle", "purge", "cycle", "purge"]


def test_a_purge_failure_is_isolated(caplog):
    attempts = []

    def purge():
        attempts.append(1)
        raise StoreError(SENTINEL_MESSAGE)

    with caplog.at_level(logging.DEBUG):
        _, calls = make_loop(duration=10, cycles=2, purge=purge)
    assert len(calls) == 2 and len(attempts) == 2
    assert "StoreError" in caplog.text
    assert SENTINEL_MESSAGE not in caplog.text


def test_a_crashing_cycle_does_not_kill_the_loop(caplog):
    fake = FakeTime()
    calls = []

    def bad_cycle():
        calls.append(1)
        raise RuntimeError(SENTINEL_MESSAGE)

    with caplog.at_level(logging.DEBUG):
        cycle.run_forever(
            timedelta(seconds=300),
            cycle=bad_cycle,
            clock=fake.clock,
            sleep=fake.sleep,
            stop=lambda: len(calls) >= 2,
        )
    assert len(calls) == 2
    assert "RuntimeError" in caplog.text
    assert SENTINEL_MESSAGE not in caplog.text


# --- interval setting ---------------------------------------------------------

MESSAGE = "WORKER_NOTICIAS_INTERVAL_MINUTES must be an integer from 5 to 1440"


def test_the_interval_defaults_to_30_minutes(monkeypatch):
    monkeypatch.delenv("WORKER_NOTICIAS_INTERVAL_MINUTES", raising=False)
    assert cycle.interval() == timedelta(minutes=30)


@pytest.mark.parametrize(("raw", "minutes"), [("5", 5), ("1440", 1440), (" 60 ", 60)])
def test_valid_intervals(monkeypatch, raw, minutes):
    monkeypatch.setenv("WORKER_NOTICIAS_INTERVAL_MINUTES", raw)
    assert cycle.interval() == timedelta(minutes=minutes)


@pytest.mark.parametrize("raw", ["4", "1441", "0", "-5", "abc", "", "10.5", "٣٠"])
def test_invalid_intervals_refuse_to_start_with_a_fixed_message(monkeypatch, raw):
    monkeypatch.setenv("WORKER_NOTICIAS_INTERVAL_MINUTES", raw)
    with pytest.raises(ConfigError) as excinfo:
        cycle.interval()
    assert str(excinfo.value) == MESSAGE


def test_a_stop_event_set_during_the_wait_wakes_the_real_loop_at_once():
    """The wiring of `__main__`: `sleep=stop.wait`, `stop=stop.is_set`."""
    import threading
    import time

    stop = threading.Event()
    starts = []

    def fake_cycle():
        starts.append(1)
        return cycle.CycleReport(())

    timer = threading.Timer(0.1, stop.set)
    timer.start()
    began = time.monotonic()
    try:
        cycle.run_forever(
            timedelta(seconds=30),
            cycle=fake_cycle,
            sleep=stop.wait,
            stop=stop.is_set,
        )
    finally:
        timer.cancel()
    assert time.monotonic() - began < 2
    assert starts == [1]


def test_a_same_host_redirect_to_a_forbidden_path_is_disabled_and_not_saved():
    source = BY_ID["semana-rss"]
    moved = "https://www.semana.com/private/feed.xml"

    class Redirecting(FakeFetcher):
        def __call__(self, url):
            if url == source.url:
                self.urls.append(url)
                return FetchResult(200, good_body(source), moved)
            return super().__call__(url)

    fetcher = Redirecting(robots_txt="User-agent: *\nDisallow: /private/\n")
    saver = RecordingSaver()
    report = run(fetcher, saver)
    row = by_id(report)["semana-rss"]
    assert (row.status, row.reason, row.read, row.new) == (
        "disabled",
        "disallowed",
        0,
        0,
    )
    assert all(c[0].source_id != "semana-rss" for c in saver.calls if c)
    assert by_id(report)["rcn-rss"].status == "ok"
    assert report.ok


def test_a_same_host_redirect_to_an_allowed_path_is_read_normally():
    source = BY_ID["semana-rss"]

    class Redirecting(FakeFetcher):
        def __call__(self, url):
            if url == source.url:
                self.urls.append(url)
                return FetchResult(200, good_body(source), "https://www.semana.com/ok")
            return super().__call__(url)

    report = run(Redirecting(), RecordingSaver())
    assert by_id(report)["semana-rss"].status == "ok"
