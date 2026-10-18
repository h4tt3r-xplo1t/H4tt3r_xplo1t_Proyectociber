"""Hardened HTTP client for the outlet feeds (threats 21 and 22).

Everything the worker downloads goes through `fetch`. The content of a feed is
untrusted, so a URL that comes from it must never be able to steer a request to
an internal service (SSRF), and a hostile or broken outlet must not be able to
exhaust the worker (slow or huge responses, decompression bombs).

Controls, in the order they run for every request and every redirect hop:

1. The URL is validated: https only, no userinfo, port 443, host in a fixed
   list written in this file (nothing comes from configuration or content), no
   IP literals, no characters that parsers read differently.
2. The host is resolved and EVERY returned address must be globally routable.
3. The connection goes to that validated IP (not to the name, so a second DNS
   answer cannot swap the address: DNS rebinding) while TLS still verifies the
   certificate against the host name.
4. Redirects are never followed by urllib3; only same-host ones are followed
   here, after the full validation above, at most `MAX_REDIRECTS` times.
5. Timeouts, an overall deadline and a cap on the DECODED body bound the cost.

Retry-After is deliberately ignored: honouring a number chosen by the remote
server would let it stall the worker; the fixed backoff is enough.

Errors are `FetchError` with a fixed `reason`; messages never carry the
response body or the query string of the URL. `tls` (certificate or hostname
verification failed) is final: it is never retried.
"""

import ipaddress
import logging
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import urljoin, urlsplit

import urllib3
from urllib3.exceptions import (
    ConnectTimeoutError,
    HTTPError,
    NewConnectionError,
    ReadTimeoutError,
    SSLError,
)
from urllib3.util import parse_url
from urllib3.util.ssl_match_hostname import CertificateError

logger = logging.getLogger(__name__)

# Hosts of the URLs in docs/PROJECT_CONTEXT.md section 4.
ALLOWED_HOSTS = frozenset(
    {
        "www.noticiasrcn.com",
        "www.semana.com",
        "www.noticiascaracol.com",
        "www.bluradio.com",
        "citytv.eltiempo.com",
    }
)

USER_AGENT = (
    "H4tt3rInformativoBot/0.1 "
    "(+https://github.com/h4tt3r-xplo1t/H4tt3r_xplo1t_Proyectociber)"
)
ACCEPT = "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.1"

HTTPS_PORT = 443
MAX_REDIRECTS = 3
# Three tries ride out a short outage without hammering an outlet that is down.
MAX_ATTEMPTS = 3
BACKOFF_BASE = 1.0
# Only matters if MAX_ATTEMPTS grows: with 3 attempts the delays are 1 s and 2 s.
BACKOFF_CAP = 8.0
# Real feeds and news sitemaps are far below 1 MiB; 5 MiB leaves room to grow.
MAX_BYTES = 5 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
# Bounds one fetch (all hops, retries and addresses) so a source cannot stall
# the loop that reads the other sources.
DEADLINE = 30.0
TIMEOUT = urllib3.Timeout(connect=5.0, read=10.0)
RETRY_STATUSES = frozenset({429}) | frozenset(range(500, 600))
# Not 300 (multiple choices) or 304 (not modified): they carry no target to follow.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Prefixes that are not globally routable but that `ipaddress` may not flag.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_V4_COMPATIBLE = ipaddress.ip_network("::/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class FetchError(Exception):
    """A download failed; `reason` is a fixed code, the message equals it.

    `status` is the HTTP status for the `http_status` reason and None otherwise;
    it is not part of the message.
    """

    def __init__(self, reason: str, status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    final_url: str


Resolver = Callable[[str, int], list]


def system_resolver(host: str, port: int) -> list:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def pinned_https_pool(
    ip: str, host: str, timeout: urllib3.Timeout
) -> urllib3.HTTPSConnectionPool:
    """Pool that connects to `ip` but verifies the certificate for `host`."""
    return urllib3.HTTPSConnectionPool(
        host=ip,
        port=HTTPS_PORT,
        server_hostname=host,
        assert_hostname=host,
        cert_reqs="CERT_REQUIRED",
        retries=False,
        timeout=timeout,
    )


DEFAULT_POOL_FACTORY = pinned_https_pool


def safe_url(url: str) -> str:
    """The URL without query string or fragment, the only form that is logged."""
    try:
        parts = urlsplit(url)
    except ValueError:  # e.g. an unterminated bracketed host
        return "<invalid url>"
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _has_forbidden_character(url: str) -> bool:
    """Backslashes, whitespace, control and non-ASCII characters."""
    return any(ch == "\\" or ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in url)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class ValidatedUrl(NamedTuple):
    host: str
    request: str  # path with query, as sent on the request line
    clean_url: str  # https://host + request, without fragment


def validate_url(url: str) -> ValidatedUrl:
    """Return the validated parts of `url` or raise FetchError."""
    if _has_forbidden_character(url):
        raise FetchError("malformed_url")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise FetchError("malformed_url") from exc
    if "%" in parts.netloc:
        # A percent-encoded host byte: no legitimate feed URL needs one.
        raise FetchError("malformed_url")
    if parts.scheme != "https":
        raise FetchError("scheme")
    if "@" in parts.netloc:
        raise FetchError("userinfo")
    host = parts.hostname or ""
    if _is_ip_literal(host):  # urlsplit strips the brackets of IPv6 literals
        raise FetchError("ip_literal")
    if host not in ALLOWED_HOSTS:
        raise FetchError("host_not_allowed")
    if port not in (None, HTTPS_PORT):
        raise FetchError("port")
    _check_parser_agreement(url, host, port)
    path = parts.path or "/"
    request = f"{path}?{parts.query}" if parts.query else path
    return ValidatedUrl(host, request, f"https://{host}{request}")


def _check_parser_agreement(url: str, host: str, port: int | None) -> None:
    """Reject URLs that urllib.parse and urllib3 read differently."""
    other = parse_url(url)
    if (other.scheme, (other.host or "").lower()) != ("https", host):
        raise FetchError("malformed_url")
    if other.port not in (None, port):
        raise FetchError("malformed_url")
    if other.auth:
        raise FetchError("malformed_url")


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_public(ip.ipv4_mapped)
        if ip in _V4_COMPATIBLE:
            return False
        if ip in _NAT64:
            return _is_public(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.sixtofour is not None:
            return _is_public(ip.sixtofour)
        if ip.teredo is not None:
            return False  # tunnel: server and client v4 are not under our control
    elif ip in _CGNAT:
        return False
    return ip.is_global and not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_public(host: str, resolver: Resolver) -> list[str]:
    """Resolve `host`; every answer must be public. Return them all, in order."""
    try:
        infos = resolver(host, HTTPS_PORT)
    except (OSError, UnicodeError) as exc:
        raise FetchError("dns") from exc
    addresses = []
    for info in infos:
        text = str(info[4][0]).split("%", 1)[0]  # drop an IPv6 scope id
        try:
            addresses.append(ipaddress.ip_address(text))
        except ValueError as exc:
            raise FetchError("dns") from exc
    if not addresses:
        raise FetchError("dns")
    if not all(_is_public(ip) for ip in addresses):
        raise FetchError("non_global_address")
    return list(dict.fromkeys(str(ip) for ip in addresses))


def _release(resp) -> None:
    resp.release_conn()
    resp.close()


def _declared_length(resp) -> int | None:
    value = resp.headers.get("Content-Length")
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None  # the streamed cap still applies


def _read_body(resp, max_bytes: int, deadline_at: float, clock) -> bytes:
    """Read the body, capped in decoded size and in total time.

    `read1` returns as soon as any data arrives (urllib3 2.x passes the call to
    `fp.read1`), unlike `stream`/`read`, which block until a full chunk. So the
    deadline is checked after every socket read, and a trickling server can
    overrun it by at most one read timeout.
    """
    declared = _declared_length(resp)
    if declared is not None and declared > max_bytes:
        raise FetchError("too_large")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read1(CHUNK_SIZE, decode_content=True)
        if clock() > deadline_at:
            raise FetchError("timeout")
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError("too_large")
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class _Hop:
    status: int
    body: bytes
    location: str | None


def _is_verification_failure(exc: BaseException) -> bool:
    """True when a certificate or hostname check failed (it never heals).

    urllib3 2.x wraps what the handshake raised as `SSLError(inner)`, so the
    original sits in `args` (and possibly in the cause or context chain):
    `ssl.SSLCertVerificationError` from the `ssl` module, or urllib3's own
    `CertificateError` from its hostname matching. Any other SSLError (EOF,
    reset or alert during the handshake) is transient.
    """
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, (ssl.SSLCertVerificationError, CertificateError)):
            return True
        pending.extend(a for a in current.args if isinstance(a, BaseException))
        for link in (current.__cause__, current.__context__):
            if link is not None:
                pending.append(link)
    return False


def _attempt(url, *, resolver, pool_factory, timeout, max_bytes, deadline_at, clock):
    host, request, _ = validate_url(url)
    ips = resolve_public(host, resolver)
    for position, ip in enumerate(ips):
        try:
            return _attempt_on(
                ip, host, request, pool_factory, timeout, max_bytes, deadline_at, clock
            )
        except (ConnectTimeoutError, SSLError) as exc:
            # Includes NewConnectionError. Only a failure to connect (or a
            # transient handshake failure) moves on to the next validated
            # address; a read timeout, an HTTP status, a validation error or a
            # certificate verification failure does not.
            if isinstance(exc, SSLError) and _is_verification_failure(exc):
                raise
            if position == len(ips) - 1 or clock() > deadline_at:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _attempt_on(
    ip, host, request, pool_factory, timeout, max_bytes, deadline_at, clock
):
    pool = pool_factory(ip, host, timeout)
    try:
        resp = pool.urlopen(
            "GET",
            request,
            headers={
                "Host": host,
                "User-Agent": USER_AGENT,
                "Accept": ACCEPT,
                "Accept-Encoding": "gzip, deflate",
            },
            redirect=False,
            retries=False,
            preload_content=False,
            decode_content=True,
            assert_same_host=False,
        )
        try:
            if resp.status in REDIRECT_STATUSES:
                return _Hop(resp.status, b"", resp.headers.get("Location"))
            if resp.status in RETRY_STATUSES:
                raise _Retryable("http_status", resp.status)
            if not 200 <= resp.status < 300:
                raise FetchError("http_status", resp.status)
            body = _read_body(resp, max_bytes, deadline_at, clock)
            return _Hop(resp.status, body, None)
        finally:
            _release(resp)
    finally:
        pool.close()


class _Retryable(Exception):
    def __init__(self, reason: str, status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _hop_with_retries(url, *, sleep, clock, deadline_at, **kwargs) -> _Hop:
    for attempt in range(MAX_ATTEMPTS):
        if clock() > deadline_at:
            raise FetchError("timeout")
        try:
            return _attempt(url, clock=clock, deadline_at=deadline_at, **kwargs)
        except _Retryable as exc:
            reason, status = exc.reason, exc.status
        except NewConnectionError:
            # A subclass of ConnectTimeoutError in urllib3 2.x, so it must be
            # matched before the timeouts.
            reason, status = "connection", None
        except SSLError as exc:
            if _is_verification_failure(exc):
                # Certificate or hostname verification failed: a retry gives
                # the same answer, so fail at once (and do not try other
                # addresses).
                raise FetchError("tls") from exc
            # Any other handshake failure is transient, like a lost connection.
            reason, status = "connection", None
        except ConnectTimeoutError, ReadTimeoutError:
            reason, status = "timeout", None
        except HTTPError:
            reason, status = "connection", None
        if attempt == MAX_ATTEMPTS - 1:
            raise FetchError(reason, status)
        delay = min(BACKOFF_BASE * 2**attempt, BACKOFF_CAP)
        if clock() + delay > deadline_at:
            raise FetchError("timeout")
        logger.warning("retrying %s: %s", safe_url(url), reason)
        sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


def _next_url(current: str, location: str | None) -> str:
    """Resolve and validate a redirect target; only the same host is allowed."""
    if not location:
        raise FetchError("redirect_rejected")
    try:
        target = urljoin(current, location)
        validated = validate_url(target)
    except (FetchError, ValueError) as exc:
        raise FetchError("redirect_rejected") from exc
    if validated.host != validate_url(current).host:
        raise FetchError("redirect_rejected")
    return validated.clean_url


def fetch(
    url: str,
    *,
    resolver: Resolver = system_resolver,
    pool_factory=None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    timeout: urllib3.Timeout = TIMEOUT,
    deadline: float = DEADLINE,
    max_bytes: int = MAX_BYTES,
) -> FetchResult:
    """GET `url` under every control of this module or raise FetchError."""
    factory = pool_factory or DEFAULT_POOL_FACTORY
    deadline_at = clock() + deadline
    current = url
    try:
        for redirects in range(MAX_REDIRECTS + 1):
            hop = _hop_with_retries(
                current,
                sleep=sleep,
                clock=clock,
                deadline_at=deadline_at,
                resolver=resolver,
                pool_factory=factory,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            if hop.location is None and hop.status not in REDIRECT_STATUSES:
                return FetchResult(
                    hop.status, hop.body, validate_url(current).clean_url
                )
            if redirects == MAX_REDIRECTS:
                raise FetchError("redirect_rejected")
            current = _next_url(current, hop.location)
    except FetchError as exc:
        logger.warning("fetch failed: %s %s", exc.reason, safe_url(current))
        raise
    raise AssertionError("unreachable")  # pragma: no cover
