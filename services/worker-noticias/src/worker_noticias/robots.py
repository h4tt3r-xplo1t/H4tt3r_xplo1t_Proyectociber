"""robots.txt check before a feed is read (PROJECT_CONTEXT sections 1 and 8).

A source whose outlet forbids our bot is not read. The check downloads the
`robots.txt` of the feed's host with `fetch.fetch` (same hardened client, same
User-Agent, same limits) and decides with the stdlib `urllib.robotparser`.

Which group applies: `can_fetch` is given the product token of
`fetch.USER_AGENT` (`H4tt3rInformativoBot`, no version). The stdlib looks the
token up case-insensitively among the declared agents, then falls back to any
group whose agent is a substring of the token, then to `*`. So a group for
another bot (GPTBot) does not apply to us, while a group for our token wins
over `*`. The substring rule can only over-match (a group named `bot` would
apply), which errs on the side of not reading. The decision is made on the
feed's path and query.

Outcome per RFC 9309 section 2.3.1, with the reason code of the decision:

* 2xx: the file is parsed; `allowed` or `disallowed` by its rules.
* 4xx (404, 410, 403...): no restrictions, `no_robots` (allowed). Exception:
  429 is a rate limit, not a statement about the file, so it counts as
  unavailable.
* 5xx, timeouts, network and DNS errors, an oversized file, a rejected
  redirect or any other `fetch.FetchError`: the whole host is treated as
  disallowed for this cycle, `unavailable`. Redirects follow `fetch`'s
  same-host policy.

Parsing reads at most 500 KiB (RFC 9309 section 2.5: crawlers must parse at
least that much); the rest is ignored, and a rule cut in half by the cap is
dropped. Bytes that are not UTF-8 are decoded with replacement. A UTF-8 BOM is
skipped.

The content of the file is never logged, only the decision and its reason.

NOT VERIFIED: the real `robots.txt` of the five outlets was not read (no
network access was used to write this); the manual run of task T6 confirms it.
"""

import logging
import urllib.robotparser
from collections.abc import Callable
from dataclasses import dataclass

from worker_noticias import fetch
from worker_noticias.feeds import Source

logger = logging.getLogger(__name__)

# The part of the User-Agent before "/", the name robots.txt groups refer to.
PRODUCT_TOKEN = fetch.USER_AGENT.split("/", 1)[0]
MAX_ROBOTS_BYTES = 500 * 1024
RATE_LIMITED = 429

ALLOWED = "allowed"
DISALLOWED = "disallowed"
NO_ROBOTS = "no_robots"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RobotsDecision:
    """`reason` is one of allowed, disallowed, no_robots, unavailable."""

    allowed: bool
    reason: str


Fetcher = Callable[[str], fetch.FetchResult]


def robots_url(source: Source) -> str:
    """The robots.txt URL of the feed's host (validated like any fetch)."""
    host = fetch.validate_url(source.url).host
    return fetch.validate_url(f"https://{host}/robots.txt").clean_url


def _capped_text(body: bytes) -> str:
    if len(body) > MAX_ROBOTS_BYTES:
        body = body[:MAX_ROBOTS_BYTES]
        cut = body.rfind(b"\n")
        body = body[: cut + 1] if cut >= 0 else b""
    return body.decode("utf-8-sig", errors="replace")


def _failure(error: fetch.FetchError) -> RobotsDecision:
    status = error.status
    if (
        error.reason == "http_status"
        and status is not None
        and 400 <= status < 500
        and status != RATE_LIMITED
    ):
        return RobotsDecision(True, NO_ROBOTS)
    return RobotsDecision(False, UNAVAILABLE)


def _download(source: Source, fetcher: Fetcher) -> tuple[RobotsDecision | None, str]:
    """(decision, "") when the file decides nothing, or (None, text) to parse."""
    try:
        result = fetcher(robots_url(source))
    except fetch.FetchError as exc:
        return _failure(exc), ""
    return None, _capped_text(result.body)


def _decide(source: Source, text: str) -> RobotsDecision:
    parser = urllib.robotparser.RobotFileParser()
    parser.parse(text.splitlines())
    if parser.can_fetch(PRODUCT_TOKEN, source.url):
        return RobotsDecision(True, ALLOWED)
    return RobotsDecision(False, DISALLOWED)


def _record(source: Source, decision: RobotsDecision) -> RobotsDecision:
    logger.info(
        "robots %s: %s allowed=%s",
        source.id,
        decision.reason,
        decision.allowed,
    )
    return decision


def check(source: Source, *, fetcher: Fetcher = fetch.fetch) -> RobotsDecision:
    """Whether `source` may be read; downloads the host's robots.txt."""
    decision, text = _download(source, fetcher)
    return _record(source, decision or _decide(source, text))


class RobotsCache:
    """One robots.txt download per host for the lifetime of the object.

    Create one per cycle. The text (or the failure) is kept per host; the
    decision is still made per feed, because the rules depend on its path.
    """

    def __init__(self, fetcher: Fetcher = fetch.fetch):
        self._fetcher = fetcher
        self._by_host: dict[str, tuple[RobotsDecision | None, str]] = {}

    def check(self, source: Source) -> RobotsDecision:
        host = fetch.validate_url(source.url).host
        if host not in self._by_host:
            self._by_host[host] = _download(source, self._fetcher)
        decision, text = self._by_host[host]
        return _record(source, decision or _decide(source, text))
