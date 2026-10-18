"""Tests for the hardened HTTP client (threats 21 and 22).

No test touches the network: DNS is a fake resolver and the connection pool is
a fake factory, except the slow-server test, which talks to a local stdlib
server on 127.0.0.1 through the same pool-factory seam.
"""

import gzip
import http.server
import io
import socket
import ssl
import threading

import pytest
import urllib3
from urllib3.exceptions import (
    ConnectTimeoutError,
    NewConnectionError,
    ReadTimeoutError,
)
from urllib3.util.ssl_match_hostname import CertificateError

from worker_noticias import fetch
from worker_noticias.fetch import FetchError
from worker_noticias.fetch import fetch as do_fetch

HOST = "www.semana.com"
URL = f"https://{HOST}/arc/outboundfeeds/rss/?outputType=xml"
PUBLIC_IP = "93.184.216.34"


def addr(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 443, 0, 0) if ":" in ip else (ip, 443)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def resolver_to(*ips):
    calls = []

    def resolver(host, port):
        calls.append((host, port))
        return [addr(ip) for ip in ips]

    resolver.calls = calls
    return resolver


def response(status=200, body=b"<rss/>", headers=None):
    return urllib3.HTTPResponse(
        body=io.BytesIO(body),
        headers=headers or {},
        status=status,
        preload_content=False,
    )


class FakePool:
    def __init__(self, script):
        self.script = script
        self.requests = []
        self.closed = False

    def urlopen(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


class FakeFactory:
    """Records how pools are built and hands out scripted responses."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls = []
        self.pools = []

    def __call__(self, ip, host, timeout):
        self.calls.append((ip, host, timeout))
        pool = FakePool(self.script)
        self.pools.append(pool)
        return pool

    @property
    def requests(self):
        return [r for pool in self.pools for r in pool.requests]


def run(url=URL, *script, resolver=None, **kwargs):
    factory = FakeFactory(*script)
    sleeps = []
    result = do_fetch(
        url,
        resolver=resolver or resolver_to(PUBLIC_IP),
        pool_factory=factory,
        sleep=sleeps.append,
        **kwargs,
    )
    return result, factory, sleeps


def reason_of(url=URL, *script, **kwargs):
    with pytest.raises(FetchError) as excinfo:
        run(url, *script, **kwargs)
    return excinfo.value.reason


# --- URL validation -------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/feed",
        "https://evil.example/www.semana.com",
        "https://www.semana.com.evil.example/feed",
        "https://semana.com/feed",
    ],
)
def test_host_outside_the_list_is_rejected(url):
    assert reason_of(url) == "host_not_allowed"


def test_plain_http_is_rejected():
    assert reason_of(f"http://{HOST}/feed") == "scheme"


@pytest.mark.parametrize("url", ["ftp://www.semana.com/", "file:///etc/passwd"])
def test_other_schemes_are_rejected(url):
    assert reason_of(url) == "scheme"


@pytest.mark.parametrize(
    "url",
    [
        "https://93.184.216.34/feed",
        "https://127.0.0.1/feed",
        "https://[::1]/feed",
        "https://[::ffff:127.0.0.1]/feed",
        "https://169.254.169.254/latest/meta-data/",
    ],
)
def test_ip_literals_are_rejected(url):
    assert reason_of(url) == "ip_literal"


def test_userinfo_trick_is_rejected():
    assert reason_of("https://www.semana.com@evil.example/") == "userinfo"
    assert reason_of("https://user:pw@www.semana.com/") == "userinfo"


@pytest.mark.parametrize(
    "url",
    [
        "https://www.semana.com\\@evil.example/",
        "https://evil.example\\.www.semana.com/",
        "https://www.semana.com/feed\\x",
        "https://www.semana.com /feed",
        "https://www.semana.com/fe ed",
        "https://www.semana.com/\tfeed",
        "https://www.semana.com/\nfeed",
        "https://www.semana.com/\x00feed",
        "https://www.semana.com/\x7ffeed",
        "https://www.semana.com/féed",
        "https://www.sem%61na.com/feed",
        "https://www.semana.com%2f@evil.example/",
    ],
)
def test_malformed_urls_are_rejected(url):
    assert reason_of(url) == "malformed_url"


@pytest.mark.parametrize("port", ["8443", "80", "0"])
def test_ports_other_than_443_are_rejected(port):
    assert reason_of(f"https://{HOST}:{port}/feed") == "port"


def test_port_443_and_uppercase_host_are_accepted():
    result, factory, _ = run(
        "https://WWW.Semana.COM:443/feed?x=1", response(body=b"ok")
    )
    assert result.body == b"ok"
    assert factory.calls[0][1] == HOST


def test_all_five_outlet_hosts_are_in_the_list():
    assert fetch.ALLOWED_HOSTS == frozenset(
        {
            "www.noticiasrcn.com",
            "www.semana.com",
            "www.noticiascaracol.com",
            "www.bluradio.com",
            "citytv.eltiempo.com",
        }
    )


def test_a_url_the_two_parsers_disagree_on_is_rejected(monkeypatch):
    real = urllib3.util.parse_url

    def other_host(url):
        parsed = real(url)
        return parsed._replace(host="evil.example")

    monkeypatch.setattr(fetch, "parse_url", other_host)
    assert reason_of(URL) == "malformed_url"


# --- DNS and address check ------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.5",
        "::7f00:1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2002:7f00:0001::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_names_resolving_to_non_global_addresses_are_rejected(ip):
    resolver = resolver_to(ip)
    assert reason_of(URL, resolver=resolver) == "non_global_address"
    assert resolver.calls == [(HOST, 443)]


def test_mixed_answers_are_rejected():
    assert (
        reason_of(URL, resolver=resolver_to(PUBLIC_IP, "10.0.0.5"))
        == "non_global_address"
    )


def test_a_resolution_failure_is_a_dns_error():
    def failing(host, port):
        raise socket.gaierror

    assert reason_of(URL, resolver=failing) == "dns"
    assert reason_of(URL, resolver=lambda host, port: []) == "dns"


def test_public_v4_and_v6_addresses_pass():
    ipv6 = "2606:2800:220:1:248:1893:25c8:1946"
    result, factory, _ = run(URL, response(), resolver=resolver_to(ipv6, PUBLIC_IP))
    assert result.status == 200
    assert factory.calls[0][0] == ipv6  # the first validated address


# --- pinned connection and request ----------------------------------------


def test_connection_is_pinned_to_the_validated_ip_with_host_header():
    _, factory, _ = run(URL, response())
    ip, host, timeout = factory.calls[0]
    assert (ip, host) == (PUBLIC_IP, HOST)
    assert isinstance(timeout, urllib3.Timeout)
    method, path, kwargs = factory.requests[0]
    assert method == "GET"
    assert path == "/arc/outboundfeeds/rss/?outputType=xml"
    assert kwargs["headers"]["Host"] == HOST
    assert kwargs["redirect"] is False
    assert kwargs["retries"] is False
    assert kwargs["preload_content"] is False
    assert kwargs["decode_content"] is True
    assert factory.pools[0].closed


def test_production_pool_verifies_the_certificate_against_the_host():
    pool = fetch.pinned_https_pool(PUBLIC_IP, HOST, urllib3.Timeout(1, 1))
    try:
        assert isinstance(pool, urllib3.HTTPSConnectionPool)
        assert pool.host == PUBLIC_IP
        assert pool.port == 443
        assert pool.cert_reqs == "CERT_REQUIRED"
        assert pool.assert_hostname == HOST
        assert pool.conn_kw["server_hostname"] == HOST
    finally:
        pool.close()


def test_default_factory_is_the_pinned_https_pool():
    assert fetch.DEFAULT_POOL_FACTORY is fetch.pinned_https_pool


def test_user_agent_is_the_projects_own_and_not_a_browser():
    _, factory, _ = run(URL, response())
    headers = factory.requests[0][2]["headers"]
    assert headers["User-Agent"] == fetch.USER_AGENT
    assert fetch.USER_AGENT.startswith("H4tt3rInformativoBot/")
    for browser in ("Mozilla", "Chrome", "Safari", "Gecko", "Googlebot"):
        assert browser not in fetch.USER_AGENT
    assert "xml" in headers["Accept"]
    assert headers["Accept-Encoding"] == "gzip, deflate"
    assert not {"Cookie", "Authorization"} & set(headers)


# --- redirects --------------------------------------------------------------


def redirect(location, status=302):
    headers = {} if location is None else {"Location": location}
    return response(status, b"", headers)


def test_redirect_to_loopback_is_rejected():
    assert reason_of(URL, redirect("https://127.0.0.1/x")) == "redirect_rejected"


def test_redirect_to_another_allowed_host_is_rejected():
    target = "https://www.bluradio.com/feed"
    assert reason_of(URL, redirect(target)) == "redirect_rejected"


def test_redirect_to_http_is_rejected():
    assert reason_of(URL, redirect(f"http://{HOST}/feed")) == "redirect_rejected"


def test_redirect_without_location_is_rejected():
    assert reason_of(URL, redirect(None)) == "redirect_rejected"


def test_redirect_to_an_invalid_target_is_rejected():
    assert reason_of(URL, redirect("https://evil.example/")) == "redirect_rejected"


def test_redirect_to_the_same_host_is_followed_after_revalidation():
    resolver = resolver_to(PUBLIC_IP)
    result, factory, _ = run(
        URL,
        redirect("/new/feed.xml", 301),
        response(body=b"final"),
        resolver=resolver,
    )
    assert result.body == b"final"
    assert result.final_url == f"https://{HOST}/new/feed.xml"
    assert [r[1] for r in factory.requests] == [
        "/arc/outboundfeeds/rss/?outputType=xml",
        "/new/feed.xml",
    ]
    assert len(resolver.calls) == 2  # every hop is resolved and checked again


def test_a_redirect_that_resolves_to_a_private_address_is_rejected():
    answers = iter([[PUBLIC_IP], ["10.0.0.5"]])

    def resolver(host, port):
        return [addr(ip) for ip in next(answers)]

    assert reason_of(URL, redirect("/x"), resolver=resolver) == "non_global_address"


def test_more_than_three_hops_are_rejected():
    hops = [redirect(f"/hop{i}") for i in range(4)]
    assert reason_of(URL, *hops, response()) == "redirect_rejected"


def test_exactly_three_hops_are_followed():
    hops = [redirect(f"/hop{i}") for i in range(3)]
    result, _, _ = run(URL, *hops, response(body=b"end"))
    assert result.body == b"end"


# --- limits -----------------------------------------------------------------


def test_content_length_above_the_limit_is_rejected_before_reading():
    big = response(body=b"x" * 10, headers={"Content-Length": "10"})
    assert reason_of(URL, big, max_bytes=5) == "too_large"
    assert big.tell() == 0  # nothing was read


def test_an_invalid_content_length_is_ignored_and_the_stream_is_capped():
    resp = response(body=b"x" * 10, headers={"Content-Length": "abc"})
    assert reason_of(URL, resp, max_bytes=5) == "too_large"


def test_body_above_the_limit_without_content_length_is_cut():
    assert reason_of(URL, response(body=b"x" * 6), max_bytes=5) == "too_large"


def test_body_exactly_at_the_limit_is_accepted():
    result, _, _ = run(URL, response(body=b"x" * 5), max_bytes=5)
    assert result.body == b"x" * 5


def test_gzip_bomb_is_cut_on_the_decoded_stream():
    bomb = gzip.compress(b"\0" * (3 * 1024 * 1024))
    assert len(bomb) < 10_000
    resp = response(body=bomb, headers={"Content-Encoding": "gzip"})
    assert reason_of(URL, resp, max_bytes=1024 * 1024) == "too_large"


def test_gzip_body_within_the_limit_is_decoded():
    packed = gzip.compress(b"<rss>ok</rss>")
    resp = response(body=packed, headers={"Content-Encoding": "gzip"})
    result, _, _ = run(URL, resp)
    assert result.body == b"<rss>ok</rss>"


def test_oversize_is_not_retried():
    factory = FakeFactory(response(body=b"x" * 9), response())
    with pytest.raises(FetchError):
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=lambda s: None,
            max_bytes=5,
        )
    assert len(factory.requests) == 1


def test_overall_deadline_is_checked_while_streaming():
    now = [0.0]

    class Trickle:
        status = 200
        headers = {}

        def read1(self, amt, decode_content):
            now[0] += 1.0
            return b"x"

        def release_conn(self):
            pass

        def close(self):
            pass

    factory = FakeFactory(Trickle())
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=lambda s: None,
            clock=lambda: now[0],
            deadline=3.0,
        )
    assert excinfo.value.reason == "timeout"
    assert len(factory.requests) == 1  # the deadline is not retried


def test_the_connection_is_released_on_success_and_on_error():
    class Spy:
        status = 200
        headers = {}

        def __init__(self, error=None):
            self.error = error
            self.released = self.closed = False

        def read1(self, amt, decode_content):
            if self.error:
                raise self.error
            return b""

        def release_conn(self):
            self.released = True

        def close(self):
            self.closed = True

    ok = Spy()
    run(URL, ok)
    assert ok.released and ok.closed

    failing = Spy(ReadTimeoutError(None, URL, "slow"))
    with pytest.raises(FetchError):
        run(URL, failing, failing, failing)
    assert failing.released and failing.closed


# --- retries ----------------------------------------------------------------


def test_503_is_retried_with_backoff_then_succeeds():
    result, factory, sleeps = run(
        URL, response(503), response(503), response(body=b"fine")
    )
    assert result.body == b"fine"
    assert len(factory.requests) == 3
    assert sleeps == [1.0, 2.0]


def test_429_is_retried():
    result, _, sleeps = run(URL, response(429), response(body=b"fine"))
    assert result.status == 200
    assert sleeps == [1.0]


def test_retry_after_is_ignored():
    _, _, sleeps = run(
        URL,
        response(429, headers={"Retry-After": "3600"}),
        response(),
    )
    assert sleeps == [1.0]


def test_404_is_not_retried():
    factory = FakeFactory(response(404), response())
    sleeps = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert excinfo.value.reason == "http_status"
    assert len(factory.requests) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    ("script", "status"),
    [
        ((response(404),), 404),
        ((response(410),), 410),
        ((response(403),), 403),
        ((response(429), response(429), response(429)), 429),
        ((response(500), response(502), response(503)), 503),
    ],
)
def test_an_http_status_error_carries_the_final_status(script, status):
    with pytest.raises(FetchError) as excinfo:
        run(URL, *script)
    assert excinfo.value.reason == "http_status"
    assert excinfo.value.status == status


def test_errors_other_than_http_status_have_no_status():
    with pytest.raises(FetchError) as excinfo:
        run(URL, *[ReadTimeoutError(None, URL, "slow")] * 3)
    assert excinfo.value.reason == "timeout"
    assert excinfo.value.status is None


def test_gives_up_after_three_attempts():
    factory = FakeFactory(response(500), response(502), response(503), response())
    sleeps = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert excinfo.value.reason == "http_status"
    assert len(factory.requests) == 3
    assert sleeps == [1.0, 2.0]


def test_connection_errors_are_retried_and_reported():
    err = NewConnectionError(None, "boom")
    result, _, sleeps = run(URL, err, response(body=b"fine"))
    assert result.body == b"fine"
    assert sleeps == [1.0]
    assert reason_of(URL, err, err, err) == "connection"


def test_timeouts_are_retried_and_reported():
    err = ConnectTimeoutError(None, "slow")
    assert reason_of(URL, err, err, err) == "timeout"
    result, _, _ = run(URL, ReadTimeoutError(None, URL, "slow"), response())
    assert result.status == 200


def _wrapped(inner):
    # urllib3 wraps what the handshake raised as SSLError(inner); with
    # retries=False the wrapper is what reaches the caller.
    return urllib3.exceptions.SSLError(inner)


def _verification_failures():
    return [
        _wrapped(ssl.SSLCertVerificationError(1, "certificate verify failed")),
        _wrapped(CertificateError("hostname 'x' doesn't match 'y'")),
    ]


@pytest.mark.parametrize("err", _verification_failures())
def test_verification_failures_fail_at_once_with_their_own_reason(err):
    # A certificate or hostname verification failure does not heal with a
    # retry, nor with another address: no retry, no fallback.
    factory = FakeFactory(err, err, err)
    sleeps = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP, "93.184.216.35"),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert excinfo.value.reason == "tls"
    assert len(factory.requests) == 1 and sleeps == []


def test_handshake_eof_is_transient_and_ends_as_connection():
    err = _wrapped(ssl.SSLEOFError(8, "EOF occurred in violation of protocol"))
    factory = FakeFactory(*[err] * 10)
    sleeps = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert excinfo.value.reason == "connection"
    assert len(factory.requests) == fetch.MAX_ATTEMPTS
    assert len(sleeps) == fetch.MAX_ATTEMPTS - 1


def test_handshake_eof_tries_the_next_validated_address():
    err = _wrapped(ssl.SSLEOFError(8, "EOF"))
    result, factory, _ = run(
        URL,
        err,
        response(body=b"fine"),
        resolver=resolver_to(PUBLIC_IP, "93.184.216.35"),
    )
    assert result.body == b"fine"
    assert len(factory.calls) == 2


def test_handshake_reset_is_retried_with_backoff():
    err = _wrapped(ssl.SSLError("tlsv1 alert internal error"))
    result, _, sleeps = run(URL, err, response(body=b"fine"))
    assert result.body == b"fine" and sleeps == [1.0]


def test_validation_errors_are_not_retried():
    factory = FakeFactory(response())
    sleeps = []
    with pytest.raises(FetchError):
        do_fetch(
            "https://example.com/",
            resolver=resolver_to(PUBLIC_IP),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert factory.calls == [] and sleeps == []


def test_error_messages_never_include_the_body_or_the_query():
    secret = b"SECRET-BODY"
    with pytest.raises(FetchError) as excinfo:
        run(
            "https://www.semana.com/feed?token=hunter2",
            response(500, secret),
            response(500, secret),
            response(500, secret),
        )
    text = str(excinfo.value)
    assert "SECRET-BODY" not in text and "hunter2" not in text
    assert text == "http_status"


def test_safe_url_drops_query_and_fragment():
    assert fetch.safe_url("https://a.b/p?token=1#x") == "https://a.b/p"


@pytest.mark.parametrize("url", ["https://[::1/", "https://[bad]/x", "http://[/"])
def test_safe_url_never_raises(url):
    assert fetch.safe_url(url) == "<invalid url>"


def test_a_malformed_bracketed_host_fails_with_a_fetch_error_not_a_value_error():
    assert reason_of("https://[::1/") == "malformed_url"


# --- redirect status codes ----------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_only_the_real_redirect_statuses_are_followed(status):
    result, factory, _ = run(URL, redirect("/new.xml", status), response(body=b"moved"))
    assert result.body == b"moved"
    assert len(factory.requests) == 2


@pytest.mark.parametrize("status", [300, 304, 305, 306])
def test_other_3xx_statuses_are_http_status_errors(status):
    assert reason_of(URL, redirect("/new.xml", status)) == "http_status"


# --- named result of validate_url ---------------------------------------------


def test_validate_url_returns_named_fields():
    parts = fetch.validate_url(f"https://{HOST}/feed?x=1")
    assert parts.host == HOST
    assert parts.request == "/feed?x=1"
    assert parts.clean_url == f"https://{HOST}/feed?x=1"
    assert tuple(parts) == (HOST, "/feed?x=1", f"https://{HOST}/feed?x=1")


# --- several validated addresses ----------------------------------------------

SECOND_IP = "93.184.216.35"


def test_next_validated_address_is_tried_after_a_connection_error():
    result, factory, sleeps = run(
        URL,
        NewConnectionError(None, "refused"),
        response(body=b"second"),
        resolver=resolver_to(PUBLIC_IP, SECOND_IP),
    )
    assert result.body == b"second"
    assert [call[0] for call in factory.calls] == [PUBLIC_IP, SECOND_IP]
    assert sleeps == []  # no retry was counted


def test_next_validated_address_is_tried_after_a_connect_timeout():
    result, factory, sleeps = run(
        URL,
        ConnectTimeoutError(None, "slow"),
        response(body=b"second"),
        resolver=resolver_to(PUBLIC_IP, SECOND_IP),
    )
    assert result.body == b"second"
    assert [call[0] for call in factory.calls] == [PUBLIC_IP, SECOND_IP]
    assert sleeps == []


def test_a_read_timeout_does_not_try_another_address():
    result, factory, sleeps = run(
        URL,
        ReadTimeoutError(None, URL, "slow"),
        response(body=b"retry"),
        resolver=resolver_to(PUBLIC_IP, SECOND_IP),
    )
    assert result.body == b"retry"
    # The retry starts again from the first address, after a backoff.
    assert [call[0] for call in factory.calls] == [PUBLIC_IP, PUBLIC_IP]
    assert sleeps == [1.0]


def test_an_http_status_does_not_try_another_address():
    factory = FakeFactory(response(404))
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP, SECOND_IP),
            pool_factory=factory,
            sleep=lambda s: None,
        )
    assert excinfo.value.reason == "http_status"
    assert [call[0] for call in factory.calls] == [PUBLIC_IP]


def test_every_address_failing_counts_one_attempt_then_retries():
    err = NewConnectionError(None, "refused")
    factory = FakeFactory(err, err, err, err, err, err)
    sleeps = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP, SECOND_IP),
            pool_factory=factory,
            sleep=sleeps.append,
        )
    assert excinfo.value.reason == "connection"
    assert len(factory.calls) == 6  # 3 attempts x 2 addresses
    assert sleeps == [1.0, 2.0]


def test_a_non_public_address_in_the_answer_still_rejects_all_of_them():
    assert (
        reason_of(URL, response(), resolver=resolver_to(PUBLIC_IP, "10.0.0.1"))
        == "non_global_address"
    )


def test_the_deadline_bounds_the_fallback_across_addresses():
    now = [0.0]

    def slow_fail(*_):
        now[0] += 10.0
        return NewConnectionError(None, "refused")

    class Pool(FakePool):
        def urlopen(self, *args, **kwargs):
            raise slow_fail()

    def factory(ip, host, timeout):
        factory.calls.append(ip)
        return Pool([])

    factory.calls = []
    with pytest.raises(FetchError) as excinfo:
        do_fetch(
            URL,
            resolver=resolver_to(PUBLIC_IP, SECOND_IP, "93.184.216.36"),
            pool_factory=factory,
            sleep=lambda s: None,
            clock=lambda: now[0],
            deadline=15.0,
        )
    assert excinfo.value.reason == "timeout"
    # The clock check in `_attempt` stops the fallback: after the second failure
    # the clock reads 20 s, past the 15 s deadline, so the re-raise happens before
    # the third address. The outer check in `_hop_with_retries` only runs between
    # attempts; it is what turns the re-raised error into the "timeout" reason
    # (the backoff would end past the deadline), not what stops the third address.
    assert len(factory.calls) == 2  # the third address is not tried


# --- slow server (threat 22) ------------------------------------------------


class _Stalling(http.server.BaseHTTPRequestHandler):
    release = threading.Event()

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
        self.wfile.flush()
        self.release.wait(10)  # headers sent, body never arrives

    def log_message(self, *args):
        pass


def test_a_slow_server_is_cut_within_the_timeout():
    import time

    _Stalling.release = threading.Event()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stalling)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def plain_pool(ip, host, timeout):
        return urllib3.HTTPConnectionPool("127.0.0.1", port, timeout=timeout)

    started = time.monotonic()
    try:
        with pytest.raises(FetchError) as excinfo:
            do_fetch(
                URL,
                resolver=resolver_to(PUBLIC_IP),
                pool_factory=plain_pool,
                sleep=lambda s: None,
                timeout=urllib3.Timeout(connect=0.5, read=0.3),
                deadline=2.0,
            )
    finally:
        _Stalling.release.set()
        server.shutdown()
        server.server_close()
    assert excinfo.value.reason == "timeout"
    assert time.monotonic() - started < 3.0


class _Trickling(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        import time

        self.send_response(200)
        self.send_header("Content-Length", "1000")
        self.end_headers()
        try:
            for _ in range(100):  # one byte per tick: never a read timeout
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.2)
        except OSError:
            pass

    def log_message(self, *args):
        pass


def test_a_trickling_server_is_cut_at_the_deadline():
    import time

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Trickling)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    outcome: list = []

    def plain_pool(ip, host, timeout):
        return urllib3.HTTPConnectionPool("127.0.0.1", port, timeout=timeout)

    def run():
        try:
            do_fetch(
                URL,
                resolver=resolver_to(PUBLIC_IP),
                pool_factory=plain_pool,
                sleep=lambda s: None,
                timeout=urllib3.Timeout(connect=0.5, read=1.0),
                deadline=1.0,
            )
        except FetchError as exc:
            outcome.append(exc.reason)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(5.0)
    elapsed = time.monotonic() - started
    server.shutdown()
    assert outcome == ["timeout"]
    assert elapsed < 2.5
