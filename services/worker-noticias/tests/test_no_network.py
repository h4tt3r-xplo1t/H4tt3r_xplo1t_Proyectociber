"""The test suite cannot reach the network (guard in conftest.py)."""

import socket

import pytest

from worker_noticias import fetch


def test_an_outlet_name_does_not_resolve_in_the_tests():
    with pytest.raises(OSError, match="network access is disabled"):
        socket.getaddrinfo("www.semana.com", 443)


def test_the_real_resolver_of_the_client_is_blocked_too():
    with pytest.raises(OSError, match="network access is disabled"):
        fetch.system_resolver("www.semana.com", 443)


def test_loopback_still_resolves_for_the_local_test_servers():
    assert socket.getaddrinfo("127.0.0.1", 80, type=socket.SOCK_STREAM)
