"""Tests for the robots.txt check and the User-Agent (PROJECT_CONTEXT 1 and 8).

The robots.txt of the real outlets was NOT read (no network): fixtures are
synthetic and follow the patterns recorded in PROJECT_CONTEXT section 4. Nothing
here touches the network; the fetcher is a fake.
"""

import pytest

from worker_noticias import feeds, fetch, robots
from worker_noticias.fetch import FetchError, FetchResult
from worker_noticias.robots import RobotsCache, RobotsDecision, check, robots_url

BY_ID = {source.id: source for source in feeds.SOURCES}
SEMANA = BY_ID["semana-rss"]
CARACOL = BY_ID["caracol-sitemap"]
RCN_RSS = BY_ID["rcn-rss"]
RCN_SITEMAP = BY_ID["rcn-sitemap"]
BOT_NAME = "H4tt3rInformativoBot"


class FakeFetcher:
    def __init__(self, outcome):
        self.outcome = outcome
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        body = self.outcome
        if isinstance(body, str):
            body = body.encode()
        return FetchResult(200, body, url)


def decide(source, robots_txt):
    return check(source, fetcher=FakeFetcher(robots_txt))


# --- URL and User-Agent ---------------------------------------------------------


@pytest.mark.parametrize("source", feeds.SOURCES, ids=lambda s: s.id)
def test_the_robots_url_is_the_root_of_the_feed_host(source):
    host = fetch.validate_url(source.url).host
    url = robots_url(source)
    assert url == f"https://{host}/robots.txt"
    assert fetch.validate_url(url).host == host


def test_the_fetcher_receives_exactly_the_robots_url():
    fetcher = FakeFetcher("User-agent: *\nAllow: /\n")
    check(SEMANA, fetcher=fetcher)
    assert fetcher.urls == ["https://www.semana.com/robots.txt"]


def test_the_user_agent_is_the_projects_own_and_not_a_browser():
    agent = fetch.USER_AGENT
    assert agent.startswith(f"{BOT_NAME}/")
    for browser in ("Mozilla", "Chrome", "Safari", "Gecko", "Googlebot"):
        assert browser not in agent
    assert robots.PRODUCT_TOKEN == BOT_NAME


# --- decisions ------------------------------------------------------------------


def test_disallow_all_for_everyone_disallows():
    assert decide(SEMANA, "User-agent: *\nDisallow: /\n") == RobotsDecision(
        False, "disallowed"
    )


def test_a_group_for_our_token_wins_over_the_wildcard_group():
    txt = f"User-agent: *\nAllow: /\n\nUser-agent: {BOT_NAME}\nDisallow: /arc/\n"
    assert decide(SEMANA, txt) == RobotsDecision(False, "disallowed")


def test_the_token_group_matches_case_insensitively():
    txt = "User-agent: *\nAllow: /\n\nUser-agent: h4tt3rinformativobot\nDisallow: /\n"
    assert decide(SEMANA, txt).allowed is False


def test_a_group_for_another_bot_does_not_apply_to_us():
    # The real pattern of Caracol and Blu Radio: named AI bots blocked, others not.
    txt = (
        "User-agent: GPTBot\nDisallow: /\n\n"
        "User-agent: ChatGPT-User\nDisallow: /\n\n"
        "User-agent: *\nDisallow: /buscar\n"
    )
    assert decide(CARACOL, txt) == RobotsDecision(True, "allowed")


def test_a_group_for_another_bot_without_a_wildcard_group_allows():
    assert decide(CARACOL, "User-agent: GPTBot\nDisallow: /\n").allowed is True


def test_allow_rule_for_the_rss_path_allows():
    txt = "User-agent: *\nDisallow: /\nAllow: /arc/outboundfeeds/rss/\n"
    assert decide(SEMANA, txt) == RobotsDecision(True, "allowed")


def test_the_feed_is_decided_on_path_and_query():
    feed_path = "/arc/outboundfeeds/rss/"
    blocked = decide(SEMANA, f"User-agent: *\nDisallow: {feed_path}?outputType=xml\n")
    other_query = decide(
        SEMANA, f"User-agent: *\nDisallow: {feed_path}?outputType=json\n"
    )
    assert blocked.allowed is False
    assert other_query.allowed is True


def test_a_disallow_for_a_different_path_allows_the_feed():
    assert decide(SEMANA, "User-agent: *\nDisallow: /buscar\n").allowed is True


def test_an_empty_robots_file_allows():
    assert decide(SEMANA, "") == RobotsDecision(True, "allowed")


def test_non_utf8_bytes_are_replaced_not_fatal():
    body = b"# caf\xe9 \xff\nUser-agent: *\nDisallow: /\n"
    assert decide(SEMANA, body) == RobotsDecision(False, "disallowed")


def test_a_utf8_bom_does_not_hide_the_first_group():
    body = b"\xef\xbb\xbfUser-agent: *\nDisallow: /\n"
    assert decide(SEMANA, body).allowed is False


# --- RFC 9309 matching (the stdlib robotparser is not used) ---------------------

SITEMAP_PATH = "/sitemapnews"


def test_star_and_end_anchor_block_a_path_ending_in_xml():
    sitemap = feeds.Source(
        "x", "Citytv", "sitemap", "https://citytv.eltiempo.com/sitemap-news.xml"
    )
    other = feeds.Source(
        "y", "Citytv", "sitemap", "https://citytv.eltiempo.com/sitemap-news.xml?x=1"
    )
    txt = "User-agent: *\nDisallow: /*.xml$\n"
    assert decide(sitemap, txt) == RobotsDecision(False, "disallowed")
    # `$` anchors the end of path+query: with a query the path no longer ends there.
    assert decide(other, txt) == RobotsDecision(True, "allowed")


def test_a_star_pattern_matches_the_query_of_the_feed():
    txt = "User-agent: *\nDisallow: /*outputType=xml\n"
    assert decide(SEMANA, txt) == RobotsDecision(False, "disallowed")
    assert decide(SEMANA, "User-agent: *\nDisallow: /*outputType=json\n").allowed


def test_the_longest_rule_wins_when_disallow_is_the_more_specific():
    txt = "User-agent: *\nAllow: /arc/\nDisallow: /arc/outboundfeeds/\n"
    assert decide(SEMANA, txt) == RobotsDecision(False, "disallowed")


def test_the_longest_rule_wins_when_allow_is_the_more_specific():
    txt = "User-agent: *\nDisallow: /arc/\nAllow: /arc/outboundfeeds/\n"
    assert decide(SEMANA, txt) == RobotsDecision(True, "allowed")


def test_on_equal_length_allow_wins_in_any_order():
    for lines in ("Allow: /arc/\nDisallow: /arc/", "Disallow: /arc/\nAllow: /arc/"):
        assert decide(SEMANA, f"User-agent: *\n{lines}\n").allowed is True


def test_the_length_of_a_pattern_counts_its_wildcards():
    # "/arc/*/rss/" (11) beats "/arc/" (5) even though both match.
    txt = "User-agent: *\nAllow: /arc/\nDisallow: /arc/*/rss/\n"
    assert decide(SEMANA, txt).allowed is False


def test_an_empty_disallow_allows_everything():
    assert decide(SEMANA, "User-agent: *\nDisallow:\n") == RobotsDecision(
        True, "allowed"
    )


def test_an_empty_disallow_does_not_cancel_another_rule_of_the_group():
    txt = "User-agent: *\nDisallow:\nDisallow: /arc/\n"
    assert decide(SEMANA, txt).allowed is False


def test_our_group_overrides_the_wildcard_group_even_when_more_permissive():
    txt = f"User-agent: *\nDisallow: /\n\nUser-agent: {BOT_NAME}\nDisallow: /buscar\n"
    assert decide(SEMANA, txt) == RobotsDecision(True, "allowed")


def test_an_agent_group_that_only_contains_part_of_our_token_does_not_apply():
    # Product token matched exactly (no substring): "bot" and "H4tt3r" are others.
    txt = "User-agent: bot\nDisallow: /\n\nUser-agent: H4tt3r\nDisallow: /\n"
    assert decide(SEMANA, txt).allowed is True


def test_a_gptbot_group_does_not_apply_and_wildcard_does():
    txt = "User-agent: GPTBot\nAllow: /\n\nUser-agent: *\nDisallow: /arc/\n"
    assert decide(SEMANA, txt).allowed is False


def test_groups_of_our_agent_are_merged():
    txt = (
        f"User-agent: {BOT_NAME}\nDisallow: /buscar\n\n"
        "User-agent: *\nDisallow: /\n\n"
        f"User-agent: {BOT_NAME}\nDisallow: /arc/\n"
    )
    assert decide(SEMANA, txt).allowed is False


def test_consecutive_user_agent_lines_form_one_group():
    txt = f"User-agent: GPTBot\nUser-agent: {BOT_NAME}\nDisallow: /\n"
    assert decide(SEMANA, txt).allowed is False


def test_a_missing_blank_line_still_starts_a_new_group():
    txt = f"User-agent: GPTBot\nDisallow: /\nUser-agent: {BOT_NAME}\nAllow: /\n"
    assert decide(SEMANA, txt).allowed is True


def test_field_names_are_case_insensitive_and_comments_are_ignored():
    txt = "USER-AGENT: * # everyone\nDISALLOW: /arc/ # no\nsitemap: https://x/y\n"
    assert decide(SEMANA, txt).allowed is False


def test_an_empty_group_for_our_token_is_still_our_group():
    # RFC 9309: a group with no rules allows everything; no fallback to `*`.
    txt = f"User-agent: *\nDisallow: /\nUser-agent: {BOT_NAME}\n"
    assert decide(SEMANA, txt).allowed is True


def test_a_group_for_our_token_with_only_unknown_lines_is_still_ours():
    txt = f"User-agent: *\nDisallow: /\nUser-agent: {BOT_NAME}\nCrawl-delay: 5\n"
    assert decide(SEMANA, txt).allowed is True


def test_unknown_lines_do_not_break_a_group():
    txt = "User-agent: *\nCrawl-delay: 10\nSitemap: https://x/s.xml\nDisallow: /\n"
    assert decide(SEMANA, txt).allowed is False


def test_rules_before_any_user_agent_are_ignored():
    assert decide(SEMANA, "Disallow: /\nUser-agent: GPTBot\nDisallow: /\n").allowed


def test_crlf_and_cr_line_endings_work():
    assert decide(SEMANA, "User-agent: *\r\nDisallow: /\r\n").allowed is False
    assert decide(SEMANA, "User-agent: *\rDisallow: /\r").allowed is False


def test_percent_encoding_is_compared_in_one_canonical_form():
    accent = feeds.Source(
        "z", "RCN", "rss", "https://www.noticiasrcn.com/secci%C3%B3n/feed"
    )
    # Raw UTF-8, lowercase hex and uppercase hex all name the same octets.
    for rule in ("/sección/", "/secci%c3%b3n/", "/secci%C3%B3n/"):
        assert decide(accent, f"User-agent: *\nDisallow: {rule}\n").allowed is False
    # Unreserved characters written as %XX equal themselves (%61 is "a").
    assert decide(SEMANA, "User-agent: *\nDisallow: /%61rc/\n").allowed is False


def test_an_encoded_reserved_character_is_not_the_plain_one():
    txt = "User-agent: *\nDisallow: /arc%2Foutboundfeeds/\n"
    assert decide(SEMANA, txt).allowed is True


def test_an_encoded_star_is_literal():
    assert decide(SEMANA, "User-agent: *\nDisallow: /%2Aarc/\n").allowed is True


def test_the_matcher_is_not_exponential_on_many_wildcards():
    txt = "User-agent: *\nDisallow: /" + "*a" * 200 + "b\n"
    assert decide(SEMANA, txt).allowed is True


# --- status handling (RFC 9309 2.3.1) -------------------------------------------


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
def test_a_4xx_means_no_restrictions(status):
    result = decide(SEMANA, FetchError("http_status", status))
    assert result == RobotsDecision(True, "no_robots")


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_5xx_disallows_for_this_cycle(status):
    result = decide(SEMANA, FetchError("http_status", status))
    assert result == RobotsDecision(False, "unavailable")


def test_429_is_treated_as_unavailable_not_as_no_robots():
    result = decide(SEMANA, FetchError("http_status", 429))
    assert result == RobotsDecision(False, "unavailable")


@pytest.mark.parametrize(
    "reason",
    ["timeout", "connection", "dns", "too_large", "redirect_rejected", "http_status"],
)
def test_any_other_fetch_error_disallows(reason):
    # "http_status" without a status (e.g. a 3xx) is also unavailable.
    assert decide(SEMANA, FetchError(reason)) == RobotsDecision(False, "unavailable")


# --- size cap (RFC 9309 2.5) ----------------------------------------------------


def test_only_the_first_500_kib_are_parsed():
    cap = 500 * 1024
    head = "User-agent: *\n"
    filler = "# " + "x" * 98 + "\n"
    padding = filler * ((cap - len(head)) // len(filler))
    assert len((head + padding).encode()) <= cap
    # The rule sits right after the cap: ignored.
    beyond = head + padding + "\n" * (cap - len((head + padding).encode()))
    beyond += "Disallow: /\n"
    assert len(beyond.encode()) > cap
    assert decide(SEMANA, beyond).allowed is True
    # The same rule inside the cap is honoured.
    assert decide(SEMANA, head + "Disallow: /\n" + padding).allowed is False


def test_a_rule_cut_in_half_by_the_cap_is_dropped():
    cap = 500 * 1024
    head = "User-agent: *\nAllow: /\n"
    pad = "\n" * (cap - len(head) - len("Disallow: /arc"))
    # "Disallow: /arc/outboundfeeds" is cut after "/arc", which would match the feed.
    txt = head + pad + "Disallow: /arc/outboundfeeds/rss/xyz\n"
    assert decide(SEMANA, txt).allowed is True


# --- cache ----------------------------------------------------------------------


def test_the_cache_downloads_once_per_host():
    fetcher = FakeFetcher("User-agent: *\nDisallow: /sitemapnews\n")
    cache = RobotsCache(fetcher)
    first = cache.check(RCN_RSS)
    second = cache.check(RCN_SITEMAP)
    assert fetcher.urls == ["https://www.noticiasrcn.com/robots.txt"]
    # Same file, but the decision is per feed path.
    assert first.allowed is True
    assert second.allowed is False


def test_the_cache_keeps_a_failure_for_the_cycle():
    fetcher = FakeFetcher(FetchError("timeout"))
    cache = RobotsCache(fetcher)
    assert cache.check(RCN_RSS) == RobotsDecision(False, "unavailable")
    assert cache.check(RCN_SITEMAP) == RobotsDecision(False, "unavailable")
    assert len(fetcher.urls) == 1


def test_the_cache_downloads_each_host_separately():
    fetcher = FakeFetcher("User-agent: *\nAllow: /\n")
    cache = RobotsCache(fetcher)
    cache.check(SEMANA)
    cache.check(CARACOL)
    assert sorted(fetcher.urls) == [
        "https://www.noticiascaracol.com/robots.txt",
        "https://www.semana.com/robots.txt",
    ]


def test_a_new_cache_downloads_again():
    fetcher = FakeFetcher("User-agent: *\nAllow: /\n")
    RobotsCache(fetcher).check(SEMANA)
    RobotsCache(fetcher).check(SEMANA)
    assert len(fetcher.urls) == 2


# --- logging --------------------------------------------------------------------


def test_the_robots_content_is_never_logged(caplog):
    caplog.set_level("DEBUG")
    decide(SEMANA, "User-agent: *\nDisallow: /\n# SECRET-MARKER\n")
    decide(SEMANA, FetchError("http_status", 503))
    assert "SECRET-MARKER" not in caplog.text
