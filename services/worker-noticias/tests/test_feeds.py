"""Tests for feed parsing and normalization (threat 20).

Fixtures are synthetic byte strings about fictitious stories; no real article
text is copied. Nothing here touches the network.
"""

import html
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from worker_noticias import feeds, fetch
from worker_noticias.feeds import FeedError, NewsItem, parse_feed

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
BY_ID = {source.id: source for source in feeds.SOURCES}
SEMANA = BY_ID["semana-rss"]
CARACOL = BY_ID["caracol-sitemap"]
HOST = "www.semana.com"

RSS_NS = (
    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:content="http://purl.org/rss/1.0/modules/content/"'
)


def esc(html_text: str) -> str:
    """HTML as a feed carries it: escaped inside the XML text."""
    return html.escape(html_text, quote=False)


def rss(*items: str) -> bytes:
    body = "".join(items)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" {RSS_NS}>'
        f"<channel><title>Fictional outlet</title>{body}</channel></rss>"
    ).encode()


def item(
    title="Headline",
    link=f"https://{HOST}/nota/1",
    date="Thu, 15 Oct 2026 10:00:00 -0500",
    description="Short summary.",
    extra="",
) -> str:
    parts = []
    if title is not None:
        parts.append(f"<title>{title}</title>")
    if link is not None:
        parts.append(f"<link>{link}</link>")
    if date is not None:
        parts.append(f"<pubDate>{date}</pubDate>")
    if description is not None:
        parts.append(f"<description>{description}</description>")
    return f"<item>{''.join(parts)}{extra}</item>"


SITEMAP_NS = (
    'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
    'xmlns:news="http://www.google.com/schemas/sitemap-news/0.9"'
)


def sitemap(*entries: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><urlset {SITEMAP_NS}>'
        f"{''.join(entries)}</urlset>"
    ).encode()


def news_url(
    loc="https://www.noticiascaracol.com/mundo/a-1",
    title="Sitemap headline",
    date="2026-10-15T09:30:00-05:00",
    outlet_name="Another Name",
) -> str:
    parts = [f"<loc>{loc}</loc>", "<news:news>"]
    parts.append(
        f"<news:publication><news:name>{outlet_name}</news:name>"
        "<news:language>es</news:language></news:publication>"
    )
    if date is not None:
        parts.append(f"<news:publication_date>{date}</news:publication_date>")
    if title is not None:
        parts.append(f"<news:title>{title}</news:title>")
    parts.append("</news:news>")
    return f"<url>{''.join(parts)}</url>"


def parse_rss(*items, now=NOW):
    return parse_feed(SEMANA, rss(*items), now=now)


def parse_sitemap(*entries, now=NOW):
    return parse_feed(CARACOL, sitemap(*entries), now=now)


# --- catalog ------------------------------------------------------------------


def test_the_catalog_has_the_six_feeds_of_the_project_context():
    assert {s.url for s in feeds.SOURCES} == {
        "https://www.noticiasrcn.com/feed-kiosko-google",
        "https://www.noticiasrcn.com/sitemapnews",
        "https://www.semana.com/arc/outboundfeeds/rss/?outputType=xml",
        "https://www.noticiascaracol.com/content-sitemap.xml",
        "https://www.bluradio.com/content-sitemap-latest.xml",
        "https://citytv.eltiempo.com/sitemap-news.xml",
    }
    assert {(s.id, s.kind) for s in feeds.SOURCES} >= {
        ("semana-rss", "rss"),
        ("caracol-sitemap", "sitemap"),
    }
    assert len({s.id for s in feeds.SOURCES}) == 6


@pytest.mark.parametrize("source", feeds.SOURCES, ids=lambda s: s.id)
def test_every_catalog_url_passes_the_fetch_validation(source):
    validated = fetch.validate_url(source.url)
    assert validated.host in fetch.ALLOWED_HOSTS
    assert source.kind in {"rss", "sitemap"}
    assert source.outlet


# --- safe XML (threat 20) -----------------------------------------------------

XXE = b"""<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
<rss version="2.0"><channel><item><title>&e;</title>
<link>https://www.semana.com/a</link></item></channel></rss>"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<rss version="2.0"><channel><item><title>&lol3;</title></item></channel></rss>"""

PLAIN_DOCTYPE = b"""<?xml version="1.0"?>
<!DOCTYPE rss>
<rss version="2.0"><channel></channel></rss>"""


def test_an_external_entity_is_rejected_and_never_read():
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, XXE, now=NOW)
    assert excinfo.value.reason in {"dtd", "entities"}
    assert "root:" not in str(excinfo.value)


def test_billion_laughs_is_rejected_without_expanding():
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, BILLION_LAUGHS, now=NOW)
    assert excinfo.value.reason in {"dtd", "entities"}


def test_a_plain_doctype_is_rejected():
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, PLAIN_DOCTYPE, now=NOW)
    assert excinfo.value.reason == "dtd"


@pytest.mark.parametrize(
    "data", [b"", b"not xml at all", b"<rss><channel></rss>", b"<rss version='2.0'>"]
)
def test_malformed_xml_is_rejected(data):
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, data, now=NOW)
    assert excinfo.value.reason == "malformed"


def test_input_above_the_byte_cap_is_rejected_before_parsing(monkeypatch):
    called = []
    monkeypatch.setattr(
        feeds.defusedxml.ElementTree,
        "fromstring",
        lambda *a, **k: called.append(1),
    )
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, b"x" * (fetch.MAX_BYTES + 1), now=NOW)
    assert excinfo.value.reason == "too_large"
    assert called == []


def test_the_parser_is_called_with_every_defusedxml_guard(monkeypatch):
    seen = {}
    real = feeds.defusedxml.ElementTree.fromstring

    def spy(data, **kwargs):
        seen.update(kwargs)
        return real(data, **kwargs)

    monkeypatch.setattr(feeds.defusedxml.ElementTree, "fromstring", spy)
    parse_rss(item())
    assert seen == {
        "forbid_dtd": True,
        "forbid_entities": True,
        "forbid_external": True,
    }


def test_the_module_imports_no_unsafe_xml_library():
    source = Path(feeds.__file__).read_text()
    imports = re.findall(r"^\s*(?:from|import)\s+([\w.]+)", source, re.MULTILINE)
    forbidden = ("xml.etree", "xml.dom", "xml.sax", "xml.parsers", "lxml")
    assert not [name for name in imports if name.startswith(forbidden)]
    assert "# noqa" not in source


# --- RSS 2.0 ------------------------------------------------------------------


def test_a_valid_rss_item_is_normalized():
    result = parse_rss(
        item(
            title="  " + esc("<b>Fictional</b> &amp; bold") + "   headline ",
            link=f"https://{HOST}/nota/1?ref=rss#comentarios",
            description=esc("<p>First <em>part</em>&nbsp;of the story &lt;3</p>"),
            extra="<dc:creator>Ana Ficticia</dc:creator>",
        )
    )
    assert result.skipped == 0
    assert result.items == [
        NewsItem(
            outlet="Semana",
            title="Fictional & bold headline",
            link=f"https://{HOST}/nota/1?ref=rss",
            published_at=datetime(2026, 10, 15, 15, 0, tzinfo=UTC),
            summary="First part of the story <3",
            author="Ana Ficticia",
            source_id="semana-rss",
        )
    ]


def test_the_date_with_an_offset_is_converted_to_utc():
    [parsed] = parse_rss(item(date="Fri, 16 Oct 2026 01:30:00 +0200")).items
    assert parsed.published_at == datetime(2026, 10, 15, 23, 30, tzinfo=UTC)
    assert parsed.published_at.utcoffset() == timedelta(0)


def test_the_author_element_is_used_when_there_is_no_dc_creator():
    [parsed] = parse_rss(item(extra="<author>Luis Ficticio</author>")).items
    assert parsed.author == "Luis Ficticio"


def test_an_email_in_the_author_element_is_not_stored():
    [parsed] = parse_rss(item(extra="<author>reporter@example.invalid</author>")).items
    assert parsed.author is None


def test_an_overlong_link_is_skipped():
    result = parse_rss(item(link=f"https://{HOST}/" + "a" * feeds.LINK_MAX))
    assert result.items == [] and result.skipped == 1


def test_no_author_and_no_description_are_none():
    [parsed] = parse_rss(item(description=None)).items
    assert parsed.author is None
    assert parsed.summary is None


def test_content_encoded_is_ignored():
    [parsed] = parse_rss(
        item(
            description="short",
            extra="<content:encoded><![CDATA[<p>FULL ARTICLE BODY</p>]]>"
            "</content:encoded>",
        )
    ).items
    assert parsed.summary == "short"
    assert "FULL ARTICLE" not in repr(parsed)
    assert not any("content" in name for name in NewsItem.__dataclass_fields__)


def test_a_script_in_the_description_becomes_plain_text_without_tags():
    [parsed] = parse_rss(
        item(
            title="Hi",
            description=esc("Safe <script>alert(1)</script> text <img src=x>"),
        )
    ).items
    assert parsed.summary == "Safe alert(1) text"


def test_markup_in_the_title_is_stripped():
    [parsed] = parse_rss(item(title=esc("<img src=x onerror=alert(1)>Plain"))).items
    assert parsed.title == "Plain"


def test_control_characters_are_removed_and_whitespace_collapsed():
    # Raw U+007F, U+0085 (NEL) and U+200B (zero width space, a format character)
    # are valid XML; entity-encoded ones are unescaped later and also removed.
    [parsed] = parse_rss(
        item(
            title="A\x7fB\u0085C\u200bD\n\t  E",
            description="x\x7fy &amp;#7; &amp;#8203;z",
        )
    ).items
    assert parsed.title == "ABCD E"
    assert parsed.summary == "xy z"


def test_long_text_is_trimmed_on_a_character_boundary():
    [parsed] = parse_rss(
        item(
            title="é" * 400,
            description="ñ" * 900,
            extra="<dc:creator>" + "ü" * 300 + "</dc:creator>",
        )
    ).items
    assert parsed.title == "é" * 300
    assert parsed.summary == "ñ" * 500
    assert parsed.author == "ü" * 120


@pytest.mark.parametrize("title", [None, "", "   ", "<b></b>"])
def test_an_item_without_a_title_is_skipped(title):
    result = parse_rss(item(title=title), item(title="Kept"))
    assert [i.title for i in result.items] == ["Kept"]
    assert result.skipped == 1


def test_a_feed_without_items_returns_nothing():
    assert parse_rss().items == []


# --- links --------------------------------------------------------------------


@pytest.mark.parametrize(
    "link",
    [
        "https://www.noticiasrcn.com/nota/1",  # another allowed outlet's host
        "https://evil.example/nota/1",
        "http://www.semana.com/nota/1",
        "https://user:pw@www.semana.com/nota/1",
        "https://www.semana.com@evil.example/nota/1",
        "https://127.0.0.1/nota/1",
        "https://www.semana.com:8443/nota/1",
        "/nota/relative",
        "javascript:alert(1)",
        "",
        None,
    ],
)
def test_an_item_with_a_link_off_the_outlet_host_is_skipped(link):
    result = parse_rss(item(link=link))
    assert result.items == []
    assert result.skipped == 1


def test_the_fragment_is_stripped_and_the_query_kept():
    [parsed] = parse_rss(item(link=f"https://{HOST}/n?id=7&amp;x=y#frag")).items
    assert parsed.link == f"https://{HOST}/n?id=7&x=y"


# --- dates --------------------------------------------------------------------


@pytest.mark.parametrize(
    "date",
    [
        None,
        "",
        "yesterday",
        "Thu, 15 Oct 2026 10:00:00",  # no zone: naive
        "Thu, 15 Oct 2026 10:00:00 -0000",  # RFC 2822 "unknown zone": naive
    ],
)
def test_a_missing_or_naive_date_is_skipped(date):
    result = parse_rss(item(date=date))
    assert result.items == []
    assert result.skipped == 1


def test_a_date_more_than_one_day_ahead_is_skipped():
    far = (NOW + timedelta(days=1, minutes=1)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    near = (NOW + timedelta(hours=23)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    result = parse_rss(item(date=far), item(date=near, title="Near"))
    assert [i.title for i in result.items] == ["Near"]
    assert result.skipped == 1


# --- Google News sitemap ------------------------------------------------------


def test_a_google_news_sitemap_entry_is_normalized():
    result = parse_sitemap(news_url())
    assert result.skipped == 0
    assert result.items == [
        NewsItem(
            outlet="Caracol",  # from the catalog, not from news:name
            title="Sitemap headline",
            link="https://www.noticiascaracol.com/mundo/a-1",
            published_at=datetime(2026, 10, 15, 14, 30, tzinfo=UTC),
            summary=None,
            author=None,
            source_id="caracol-sitemap",
        )
    ]


def test_a_sitemap_date_with_z_is_utc_and_a_naive_one_is_skipped():
    result = parse_sitemap(
        news_url(date="2026-10-15T09:30:00Z", title="Z"),
        news_url(date="2026-10-15T09:30:00", title="Naive"),
        news_url(date="2026-10-15", title="DateOnly"),
    )
    assert [i.title for i in result.items] == ["Z"]
    assert result.items[0].published_at == datetime(2026, 10, 15, 9, 30, tzinfo=UTC)
    assert result.skipped == 2


def test_a_plain_sitemap_entry_is_skipped_and_counted():
    plain = (
        "<url><loc>https://www.noticiascaracol.com/mundo/b-2</loc>"
        "<lastmod>2026-10-15</lastmod></url>"
    )
    result = parse_sitemap(plain, news_url(title="Kept"))
    assert [i.title for i in result.items] == ["Kept"]
    assert result.skipped == 1


def test_a_sitemap_entry_with_a_link_off_the_host_or_without_title_is_skipped():
    result = parse_sitemap(
        news_url(loc="https://evil.example/x"),
        news_url(loc="http://www.noticiascaracol.com/x"),
        news_url(title=None),
        news_url(date=None),
    )
    assert result.items == []
    assert result.skipped == 4


def test_a_sitemapindex_is_not_followed():
    index = (
        b'<?xml version="1.0"?><sitemapindex '
        b'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        b"<sitemap><loc>https://www.noticiascaracol.com/sub.xml</loc></sitemap>"
        b"</sitemapindex>"
    )
    with pytest.raises(FeedError) as excinfo:
        parse_feed(CARACOL, index, now=NOW)
    assert excinfo.value.reason == "unknown_format"


@pytest.mark.parametrize(
    "data",
    [
        b"<html><body>Not a feed</body></html>",
        b"<feed xmlns='http://www.w3.org/2005/Atom'/>",
    ],
)
def test_an_unknown_root_element_is_rejected(data):
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, data, now=NOW)
    assert excinfo.value.reason == "unknown_format"


def test_a_source_kind_does_not_accept_the_other_format():
    with pytest.raises(FeedError) as excinfo:
        parse_feed(SEMANA, sitemap(news_url()), now=NOW)
    assert excinfo.value.reason == "unknown_format"
    with pytest.raises(FeedError) as excinfo:
        parse_feed(CARACOL, rss(item()), now=NOW)
    assert excinfo.value.reason == "unknown_format"


def test_the_default_clock_is_used_when_now_is_not_given():
    far = (datetime.now(UTC) + timedelta(days=3)).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    result = parse_feed(SEMANA, rss(item(date=far)))
    assert result.items == [] and result.skipped == 1
