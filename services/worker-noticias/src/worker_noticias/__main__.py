"""Command line of the news worker.

    python -m worker_noticias run         # loop forever (one replica only)
    python -m worker_noticias once        # one cycle; exit 0 if no feed failed
    python -m worker_noticias check-live  # manual check, see below

`run` and `once` store the news: they need WORKER_NOTICIAS_DATABASE_URL (the
least-privilege role, see scripts/create_role.sql). `run` also reads
WORKER_NOTICIAS_INTERVAL_MINUTES (5 to 1440, default 30) and
WORKER_NOTICIAS_RETENTION_DAYS (1 to 365, default 30), and refuses to start
with a fixed message if either is invalid. SIGTERM and SIGINT end the loop
after the current cycle.

The project is not installed as a package (pyproject `package = false`), so run
the commands from services/worker-noticias with `PYTHONPATH=src`.

Manual live check, to be run by a person (it makes real requests to the
outlets; CI and the tests never do):

    PYTHONPATH=src uv run --locked python -m worker_noticias check-live

It runs one cycle against the real outlets WITHOUT the database (nothing is
saved and no database setting is needed) and prints one line per feed:
`<id> <status> read=<n> skipped=<n> reason=<code>`, never any content. The exit
code is 0 if no feed failed, 1 otherwise. Use it to confirm the real formats of
the feeds and the outlets' robots.txt before relying on the worker.

Exit codes: 0 ok, 1 a feed failed, 2 usage, 78 invalid configuration.
"""

import logging
import signal
import sys
import threading
from collections.abc import Callable
from functools import partial

from worker_noticias import cycle, fetch, store

USAGE = "usage: python -m worker_noticias {run|once|check-live}"
COMMANDS = ("run", "once", "check-live")
EXIT_USAGE = 2
EXIT_CONFIG = 78


def _discard(items) -> store.SaveResult:
    """Saver of `check-live`: nothing is stored."""
    return store.SaveResult(0, 0)


def build_cycle(
    command: str, *, fetcher: Callable[[str], fetch.FetchResult] = fetch.fetch
) -> Callable[[], cycle.CycleReport]:
    """The cycle for a command; `check-live` never touches the database."""
    if command == "check-live":
        saver = _discard
    else:
        # Fail now, with a clear message, instead of once per feed.
        store.get_engine()
        saver = partial(store.save, retention=store.retention())
    return lambda: cycle.run_cycle(fetcher=fetcher, saver=saver)


def _purge() -> int:
    return store.purge(store.retention())


def _print_report(report: cycle.CycleReport) -> None:
    for r in report.sources:
        reason = r.reason or "-"
        line = f"{r.source_id} {r.status} read={r.read} skipped={r.skipped}"
        print(f"{line} reason={reason}")


def _exit_code(report: cycle.CycleReport) -> int:
    return 0 if report.ok else 1


def _run_forever(cycle_for, loop) -> int:
    wait_for = cycle.interval()
    store.retention()  # fail now, not at the first purge
    stop = threading.Event()

    def request_stop(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    loop(
        wait_for,
        cycle=cycle_for("run"),
        purge=_purge,
        sleep=stop.wait,
        stop=stop.is_set,
    )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    cycle_for: Callable[[str], Callable[[], cycle.CycleReport]] = build_cycle,
    loop=cycle.run_forever,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in COMMANDS:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    command = args[0]
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    # urllib3 retry warnings may quote request paths: keep only errors.
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    try:
        if command == "run":
            return _run_forever(cycle_for, loop)
        report = cycle_for(command)()
    except store.ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CONFIG
    if command == "check-live":
        _print_report(report)
    return _exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
