"""Tests for the command line: usage, exit codes and the manual live check.

The cycle is a fake or runs on a fake fetcher: nothing here touches the network
or the database.
"""

import signal
from datetime import timedelta

import pytest

from tests.test_cycle import SENTINEL_TITLE, FakeFetcher
from worker_noticias import __main__ as cli
from worker_noticias import cycle, store
from worker_noticias.fetch import FetchError

USAGE = "usage: python -m worker_noticias {run|once|check-live}"


@pytest.fixture(autouse=True)
def process_signal_handlers_stay_untouched():
    """No test may leave its own SIGTERM/SIGINT handlers in the test process."""
    before = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    after = {s: signal.getsignal(s) for s in before}
    for sig, handler in before.items():
        signal.signal(sig, handler)  # restore, so one leak fails one test only
    assert after == before


def report(*statuses):
    return cycle.CycleReport(
        tuple(
            cycle.SourceReport(f"s{i}", status, 3, 2, 1, reason)
            for i, (status, reason) in enumerate(statuses)
        )
    )


def fake_cycle_for(rep, seen=None):
    def cycle_for(command):
        if seen is not None:
            seen.append(command)
        return lambda: rep

    return cycle_for


@pytest.mark.parametrize(
    "argv", [[], ["bogus"], ["once", "extra"], ["--help"], ["RUN"], ["run", "once"]]
)
def test_unknown_or_missing_arguments_print_the_usage_and_exit_2(argv, capsys):
    assert cli.main(argv, cycle_for=fake_cycle_for(report())) == 2
    captured = capsys.readouterr()
    assert captured.err.strip() == USAGE
    assert captured.out == ""


def test_once_exits_0_when_every_allowed_feed_succeeded():
    seen = []
    rep = report(("ok", None), ("disabled", "disallowed"))
    assert cli.main(["once"], cycle_for=fake_cycle_for(rep, seen)) == 0
    assert seen == ["once"]


def test_once_exits_1_when_a_feed_failed():
    rep = report(("ok", None), ("failed", "fetch_timeout"))
    assert cli.main(["once"], cycle_for=fake_cycle_for(rep)) == 1


def test_check_live_prints_one_line_per_feed_and_nothing_else(capsys):
    rep = report(("ok", None), ("disabled", "disallowed"), ("failed", "feed_malformed"))
    code = cli.main(["check-live"], cycle_for=fake_cycle_for(rep))
    assert code == 1
    assert capsys.readouterr().out.splitlines() == [
        "s0 ok read=3 skipped=1 reason=-",
        "s1 disabled read=3 skipped=1 reason=disallowed",
        "s2 failed read=3 skipped=1 reason=feed_malformed",
    ]


def test_check_live_exits_0_when_everything_allowed_succeeded():
    rep = report(("ok", None))
    assert cli.main(["check-live"], cycle_for=fake_cycle_for(rep)) == 0


def test_check_live_never_saves_and_needs_no_database(monkeypatch, capsys):
    monkeypatch.delenv("WORKER_NOTICIAS_DATABASE_URL", raising=False)
    monkeypatch.delenv("WORKER_NOTICIAS_RETENTION_DAYS", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("the database must not be touched")

    monkeypatch.setattr(store, "save", forbidden)
    monkeypatch.setattr(store, "get_engine", forbidden)
    monkeypatch.setattr(store, "purge", forbidden)
    fetcher = FakeFetcher({"rcn-rss": FetchError("timeout")})
    one_cycle = cli.build_cycle("check-live", fetcher=fetcher)
    rep = one_cycle()
    assert [r.status for r in rep.sources].count("ok") == 5
    assert not rep.ok
    out = capsys.readouterr().out
    assert SENTINEL_TITLE not in out


def test_the_printed_lines_hold_no_content(capsys, monkeypatch):
    monkeypatch.delenv("WORKER_NOTICIAS_DATABASE_URL", raising=False)
    code = cli.main(
        ["check-live"],
        cycle_for=lambda command: cli.build_cycle(command, fetcher=FakeFetcher()),
    )
    assert code == 0
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 6
    assert SENTINEL_TITLE not in out
    assert "http" not in out


def test_run_hands_the_interval_and_a_stop_flag_to_the_loop(monkeypatch):
    monkeypatch.setenv("WORKER_NOTICIAS_INTERVAL_MINUTES", "10")
    handlers = {}
    monkeypatch.setattr(signal, "signal", lambda sig, fn: handlers.update({sig: fn}))
    captured = {}

    def loop(interval, **kwargs):
        captured["interval"] = interval
        captured.update(kwargs)

    code = cli.main(["run"], cycle_for=fake_cycle_for(report()), loop=loop)
    assert code == 0
    assert captured["interval"] == timedelta(minutes=10)
    assert set(handlers) == {signal.SIGTERM, signal.SIGINT}
    assert captured["stop"]() is False
    handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert captured["stop"]() is True


def test_run_refuses_to_start_with_an_invalid_interval(monkeypatch, capsys):
    monkeypatch.setenv("WORKER_NOTICIAS_INTERVAL_MINUTES", "1")
    called = []
    code = cli.main(
        ["run"],
        cycle_for=fake_cycle_for(report()),
        loop=lambda *a, **k: called.append(1),
    )
    assert code == 78
    assert called == []
    assert capsys.readouterr().err.strip() == (
        "WORKER_NOTICIAS_INTERVAL_MINUTES must be an integer from 5 to 1440"
    )


def test_run_refuses_to_start_with_an_invalid_retention(monkeypatch, capsys):
    monkeypatch.setenv("WORKER_NOTICIAS_RETENTION_DAYS", "0")
    code = cli.main(
        ["run"], cycle_for=fake_cycle_for(report()), loop=lambda *a, **k: None
    )
    assert code == 78
    assert "WORKER_NOTICIAS_RETENTION_DAYS" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["once", "run"])
def test_storing_commands_refuse_to_start_without_a_database_url(
    command, monkeypatch, capsys
):
    monkeypatch.delenv("WORKER_NOTICIAS_DATABASE_URL", raising=False)
    store.get_engine.cache_clear()
    code = cli.main(
        [command],
        cycle_for=lambda c: cli.build_cycle(c, fetcher=FakeFetcher()),
        loop=lambda *a, **k: None,
    )
    assert code == 78
    assert capsys.readouterr().err.strip() == "WORKER_NOTICIAS_DATABASE_URL is not set"
