"""Feed catalog, safe XML parsing and normalization (threat 20).

The content of a feed is untrusted: the XML can carry entities that read local
files or blow up in memory (XXE, billion laughs), the text can carry markup, and
the links can point anywhere. So:

1. The XML is parsed only with `defusedxml` and with DTDs, entities and
   external references forbidden; any parser failure becomes a `FeedError`
   with a fixed reason. Input above `fetch.MAX_BYTES` is rejected before
   parsing. No other XML library is imported here.
2. Text is reduced to plain text: tags stripped, entities unescaped once,
   control and format characters removed, whitespace collapsed, length capped.
   The result is still untrusted text and is escaped again when displayed.
3. A link is kept only if it passes `fetch.validate_url` AND is on the host of
   the feed itself. Links are data to store and show, never fetched here.
4. A date must carry a time zone (a naive one is not guessed) and cannot be
   more than one day in the future. Items failing any rule are skipped and
   counted, not repaired.
5. There is no field for the article body: only headline, link, date, a short
   summary, outlet and author. `content:encoded` is never read.

A "fuente" is one feed (ADR 0007). Formats supported: RSS 2.0 and the Google
News sitemap. A plain sitemap entry (only `loc`/`lastmod`) has no headline, so
it is skipped rather than fetching the page to find one. A `sitemapindex` is
rejected (`unknown_format`) and never followed: following it would fetch URLs
taken from content (threat 21).

NOT VERIFIED: the real formats of the Caracol and Blu Radio sitemaps (no
network access was used to write this). They are assumed to be Google News
sitemaps; the manual run of task T6 will confirm it, and a different format
will show up as `unknown_format` or as skipped entries, never as bad data.
"""

import html
import logging
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

import defusedxml
import defusedxml.ElementTree

from worker_noticias import fetch

logger = logging.getLogger(__name__)

TITLE_MAX = 300
SUMMARY_MAX = 500
AUTHOR_MAX = 120
LINK_MAX = 2000
MAX_FUTURE = timedelta(days=1)
# Real feeds carry tens of items; the cap bounds work and rows per feed.
MAX_ITEMS_PER_FEED = 500

DC = "{http://purl.org/dc/elements/1.1/}"
SITEMAP = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
NEWS = "{http://www.google.com/schemas/sitemap-news/0.9}"


@dataclass(frozen=True)
class Source:
    """One feed of one outlet."""

    id: str
    outlet: str
    kind: str  # "rss" or "sitemap"
    url: str


# URLs of docs/PROJECT_CONTEXT.md section 4. Fixed in code, like ALLOWED_HOSTS.
SOURCES = (
    Source("rcn-rss", "RCN", "rss", "https://www.noticiasrcn.com/feed-kiosko-google"),
    Source("rcn-sitemap", "RCN", "sitemap", "https://www.noticiasrcn.com/sitemapnews"),
    Source(
        "semana-rss",
        "Semana",
        "rss",
        "https://www.semana.com/arc/outboundfeeds/rss/?outputType=xml",
    ),
    Source(
        "caracol-sitemap",
        "Caracol",
        "sitemap",
        "https://www.noticiascaracol.com/content-sitemap.xml",
    ),
    Source(
        "blu-radio-sitemap",
        "Blu Radio",
        "sitemap",
        "https://www.bluradio.com/content-sitemap-latest.xml",
    ),
    Source(
        "citytv-sitemap",
        "Citytv",
        "sitemap",
        "https://citytv.eltiempo.com/sitemap-news.xml",
    ),
)


class FeedError(Exception):
    """A feed cannot be used; `reason` is a fixed code, the message equals it.

    Reasons: dtd, entities, malformed, unknown_format, too_large.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NewsItem:
    outlet: str
    title: str
    link: str
    published_at: datetime  # aware, UTC
    summary: str | None
    author: str | None
    source_id: str


@dataclass(frozen=True)
class ParseResult:
    items: list[NewsItem]
    skipped: int


class _Skip(Exception):
    """The entry breaks a rule; it is dropped and counted."""


# --- safe parsing ---------------------------------------------------------------


def _parse_xml(data: bytes):
    if len(data) > fetch.MAX_BYTES:
        raise FeedError("too_large")
    try:
        return defusedxml.ElementTree.fromstring(
            data, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except defusedxml.DTDForbidden as exc:
        raise FeedError("dtd") from exc
    except (defusedxml.EntitiesForbidden, defusedxml.ExternalReferenceForbidden) as exc:
        raise FeedError("entities") from exc
    except defusedxml.DefusedXmlException as exc:
        raise FeedError("malformed") from exc
    except defusedxml.ElementTree.ParseError as exc:
        raise FeedError("malformed") from exc


# --- normalization --------------------------------------------------------------


class _TextCollector(HTMLParser):
    """Collects the text of an HTML fragment; tags are dropped."""

    def __init__(self):
        # Character references are kept raw and unescaped once, at the end.
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")


def _plain_text(raw: str | None, limit: int) -> str | None:
    """Plain text of `raw` (or None when nothing is left), at most `limit` chars."""
    if not raw:
        return None
    collector = _TextCollector()
    collector.feed(raw)
    collector.close()
    text = html.unescape("".join(collector.parts))
    cleaned = "".join(
        " "
        if ch in "\t\n\r"
        else ""
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn")
        else ch
        for ch in text
    )
    cleaned = " ".join(cleaned.split())[:limit].rstrip()
    return cleaned or None


def _text_of(element) -> str | None:
    """All the text under an element (markup left inside is flattened)."""
    return None if element is None else "".join(element.itertext())


def _clean_link(raw: str | None, source: Source) -> str:
    if not raw or len(raw) > LINK_MAX:
        raise _Skip
    try:
        validated = fetch.validate_url(raw.strip())
    except fetch.FetchError as exc:
        raise _Skip from exc
    if validated.host != fetch.validate_url(source.url).host:
        raise _Skip
    return validated.clean_url


def _aware_utc(moment: datetime, now: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise _Skip  # a naive date is rejected, not guessed
    try:
        moment = moment.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        # An offset at the edge of the datetime range cannot be converted.
        raise _Skip from exc
    if moment > now + MAX_FUTURE:
        raise _Skip
    return moment


def _rss_date(raw: str | None, now: datetime) -> datetime:
    if not raw or not raw.strip():
        raise _Skip
    try:
        return _aware_utc(parsedate_to_datetime(raw.strip()), now)
    except (ValueError, TypeError) as exc:
        raise _Skip from exc


def _iso_date(raw: str | None, now: datetime) -> datetime:
    if not raw or not raw.strip():
        raise _Skip
    try:
        return _aware_utc(datetime.fromisoformat(raw.strip()), now)
    except ValueError as exc:
        raise _Skip from exc


def _author(entry) -> str | None:
    for tag in (f"{DC}creator", "author"):
        text = _plain_text(_text_of(entry.find(tag)), AUTHOR_MAX)
        # RSS <author> is often an e-mail address: personal data, not stored.
        if text and "@" not in text:
            return text
    return None


# --- formats --------------------------------------------------------------------


def _rss_item(source: Source, entry, now: datetime) -> NewsItem:
    title = _plain_text(_text_of(entry.find("title")), TITLE_MAX)
    if title is None:
        raise _Skip
    return NewsItem(
        outlet=source.outlet,
        title=title,
        link=_clean_link(_text_of(entry.find("link")), source),
        published_at=_rss_date(_text_of(entry.find("pubDate")), now),
        summary=_plain_text(_text_of(entry.find("description")), SUMMARY_MAX),
        author=_author(entry),
        source_id=source.id,
    )


def _sitemap_item(source: Source, entry, now: datetime) -> NewsItem:
    news = entry.find(f"{NEWS}news")
    if news is None:
        raise _Skip  # a plain entry has no headline; the page is never fetched
    title = _plain_text(_text_of(news.find(f"{NEWS}title")), TITLE_MAX)
    if title is None:
        raise _Skip
    return NewsItem(
        outlet=source.outlet,  # from the catalog, not from the feed's own name
        title=title,
        link=_clean_link(_text_of(entry.find(f"{SITEMAP}loc")), source),
        published_at=_iso_date(_text_of(news.find(f"{NEWS}publication_date")), now),
        summary=None,
        author=None,
        source_id=source.id,
    )


def _entries(source: Source, root):
    """(entry elements, builder) for the format the source is declared to use."""
    if source.kind == "rss" and root.tag == "rss":
        return root.findall("channel/item"), _rss_item
    if source.kind == "sitemap" and root.tag == f"{SITEMAP}urlset":
        return root.findall(f"{SITEMAP}url"), _sitemap_item
    # Includes `sitemapindex`, which is never followed (threat 21).
    raise FeedError("unknown_format")


def parse_feed(source: Source, data: bytes, now: datetime | None = None) -> ParseResult:
    """Parse and normalize one downloaded feed; raise FeedError if unusable."""
    root = _parse_xml(data)
    entries, build = _entries(source, root)
    now = now or datetime.now(UTC)
    items: list[NewsItem] = []
    skipped = 0
    if len(entries) > MAX_ITEMS_PER_FEED:
        # Count only: no title or link of the dropped entries is logged.
        over = len(entries) - MAX_ITEMS_PER_FEED
        logger.warning("feed %s: %d item(s) over the cap skipped", source.id, over)
        skipped += over
        entries = entries[:MAX_ITEMS_PER_FEED]
    for entry in entries:
        try:
            items.append(build(source, entry, now))
        except _Skip:
            skipped += 1
    return ParseResult(items, skipped)
