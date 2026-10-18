"""robots.txt check before a feed is read (PROJECT_CONTEXT sections 1 and 8).

A source whose outlet forbids our bot is not read. The check downloads the
`robots.txt` of the feed's host with `fetch.fetch` (same hardened client, same
User-Agent, same limits) and decides with a small matcher of its own, because
the stdlib `urllib.robotparser` does not implement RFC 9309 (first match in
file order instead of the longest match; wildcards depend on the Python
version).

Parsing: only `User-agent`, `Allow` and `Disallow` lines are read (names are
case-insensitive); anything after `#` is a comment; other lines (`Sitemap`,
`Crawl-delay`...) are ignored and do not close a group. Consecutive
`User-agent` lines share one group; a `User-agent` line after a rule starts a
new group, with or without a blank line. Rules before any `User-agent` line
are ignored. An empty `Allow`/`Disallow` value is no rule (allows everything).

Group selection (RFC 9309 section 2.2.1): the groups whose agent equals our
product token `H4tt3rInformativoBot` (`fetch.USER_AGENT` without the version),
compared case-insensitively and EXACTLY (no prefix or substring: a group named
`bot` or `H4tt3r` is another crawler's) are merged. If there is none, the
groups of `*` are merged; if there is none either, everything is allowed. When
a group for our token exists, `*` is not consulted even if ours is more
permissive.

Matching (section 2.2.2) on the feed's path plus query: every rule of the
merged group that matches is a candidate; the longest pattern wins (its length
in characters after canonicalization, `*` and `$` included); on a tie `Allow`
wins; with no match the path is allowed. `*` matches any run of characters
and a final `$` anchors the end of path+query (so `/x.xml$` does not match
`/x.xml?a=1`). The match is a linear scan over the pieces between the stars,
so a hostile pattern cannot make it exponential.

Percent-encoding: rules and path are compared in one canonical form: the text
is taken as UTF-8 octets, each octet outside printable ASCII is written
`%XX`, existing escapes get uppercase hex, and an escape of an unreserved
character (letters, digits, `-._~`) is decoded. Reserved escapes stay escaped,
so `%2F` is not `/` and `%2A` is a literal star, not a wildcard.

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
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

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


_UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_ESCAPE = re.compile(rb"%([0-9A-Fa-f]{2})")
_LINE_END = re.compile(r"\r\n|\r|\n")


def _canonical(text: str) -> str:
    """The one form rules and paths are compared in (see the module docstring)."""
    out = []
    raw = text.encode("utf-8")
    position = 0
    while position < len(raw):
        escape = _ESCAPE.match(raw, position)
        if escape:
            octet = int(escape.group(1), 16)
            position += 3
        else:
            octet = raw[position]
            position += 1
            if 0x21 <= octet <= 0x7E and octet != 0x25:  # printable, not "%"
                out.append(chr(octet))
                continue
        out.append(chr(octet) if octet in _UNRESERVED else f"%{octet:02X}")
    return "".join(out)


def _rules_for(text: str) -> list[tuple[bool, str]]:
    """(allow, canonical pattern) of the groups that apply to our token."""
    ours: list[tuple[bool, str]] = []
    wildcard: list[tuple[bool, str]] = []
    found_ours = False
    agents: list[str] = []
    in_rules = False
    for line in _LINE_END.split(text):
        field, sep, value = line.partition("#")[0].partition(":")
        field, value = field.strip().lower(), value.strip()
        if not sep:
            continue
        if field == "user-agent":
            if in_rules:
                agents, in_rules = [], False
            agents.append(value.lower())
            if value.lower() == PRODUCT_TOKEN.lower():
                # Our group exists even if it has no rules (RFC 9309): it
                # allows everything and `*` must not apply.
                found_ours = True
        elif field in ("allow", "disallow") and agents:
            in_rules = True
            if value:
                rule = (field == "allow", _canonical(value))
                if PRODUCT_TOKEN.lower() in agents:
                    ours.append(rule)
                if "*" in agents:
                    wildcard.append(rule)
    return ours if found_ours else wildcard


def _matches(pattern: str, path: str) -> bool:
    """RFC 9309 pattern: prefix match with `*` and a final `$` anchor."""
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    first, *rest = pattern.split("*")
    if not path.startswith(first):
        return False
    if not rest:
        return not anchored or path == first
    position = len(first)
    for middle in rest[:-1]:
        found = path.find(middle, position)
        if found < 0:
            return False
        position = found + len(middle)
    last = rest[-1]
    if anchored:
        return path[position:].endswith(last) and len(path) - position >= len(last)
    return path.find(last, position) >= 0


def _decide(source: Source, text: str) -> RobotsDecision:
    path = _canonical(_path_and_query(source.url))
    best_length, allowed = -1, True
    for allow, pattern in _rules_for(text):
        if _matches(pattern, path) and (
            len(pattern) > best_length or (len(pattern) == best_length and allow)
        ):
            best_length, allowed = len(pattern), allow
    return RobotsDecision(allowed, ALLOWED if allowed else DISALLOWED)


def _path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


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

    def check(self, source: Source, url: str | None = None) -> RobotsDecision:
        """Decide `source`, or `url` (same host) when it is given.

        `url` is the final URL of a redirect: the rules of the source's host
        apply to the path the content was really served from.
        """
        host = fetch.validate_url(source.url).host
        if host not in self._by_host:
            self._by_host[host] = _download(source, self._fetcher)
        decision, text = self._by_host[host]
        target = replace(source, url=url) if url else source
        return _record(source, decision or _decide(target, text))
