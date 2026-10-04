import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from gateway import tokens
from gateway.secrets import GatewayKeys
from gateway.tokens import (
    InvalidToken,
    check_csrf,
    decode_access_token,
    issue_access_token,
    login_attempt_key,
    make_csrf,
)

# Fake keys: random-looking but fixed, never used outside the tests.
KEYS = GatewayKeys(jwt_kid="kid-1", jwt_key=b"j" * 32, csrf_key=b"c" * 32)
USER_ID = uuid.UUID("12345678-1234-5678-1234-567812345678")
ISSUER = "h4tt3r-gateway-test"
AUDIENCE = "h4tt3r-web-test"


def now():
    return datetime.now(UTC)


def forge(claims=None, *, key=None, algorithm="HS256", headers=None, drop=()):
    """Sign a token with arbitrary claims, to test every rejection."""
    base = {
        "sub": str(USER_ID),
        "role": "lector",
        "sid": "sid-1",
        "jti": "jti-1",
        "iat": int(now().timestamp()),
        "nbf": int(now().timestamp()),
        "exp": int((now() + timedelta(minutes=15)).timestamp()),
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    base.update(claims or {})
    for name in drop:
        base.pop(name)
    return jwt.encode(
        base,
        KEYS.jwt_key if key is None else key,
        algorithm=algorithm,
        headers={"kid": KEYS.jwt_kid, **(headers or {})},
    )


def test_issued_token_has_the_expected_header_and_claims():
    issued_at = now()
    token, claims = issue_access_token(USER_ID, "editor", KEYS, issued_at)

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS256"
    assert header["kid"] == "kid-1"
    assert set(claims) == {
        "sub",
        "role",
        "sid",
        "jti",
        "iat",
        "nbf",
        "exp",
        "iss",
        "aud",
    }
    assert claims["sub"] == str(USER_ID)
    assert claims["role"] == "editor"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["iat"] == claims["nbf"] == int(issued_at.timestamp())
    assert claims["exp"] - claims["iat"] == 15 * 60


def test_each_token_gets_a_new_sid_and_jti():
    _, first = issue_access_token(USER_ID, "lector", KEYS, now())
    _, second = issue_access_token(USER_ID, "lector", KEYS, now())

    assert first["sid"] != second["sid"]
    assert first["jti"] != second["jti"]
    assert len(first["sid"]) >= 22  # at least 128 bits, base64url


def test_decode_returns_the_claims_of_a_valid_token():
    token, claims = issue_access_token(USER_ID, "lector", KEYS, now())

    assert decode_access_token(token, KEYS) == claims


def test_none_algorithm_is_rejected():
    token = jwt.encode(
        {"sub": "x"}, key=None, algorithm="none", headers={"kid": "kid-1"}
    )

    with pytest.raises(InvalidToken):
        decode_access_token(token, KEYS)


def test_other_hmac_algorithm_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(forge(algorithm="HS512", key=b"j" * 64), KEYS)


def test_asymmetric_algorithm_header_is_rejected():
    def b64(data: dict) -> str:
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64({"alg": "RS256", "typ": "JWT", "kid": "kid-1"})
    payload = b64({"sub": "x"})
    token = f"{header}.{payload}.c2ln"

    with pytest.raises(InvalidToken):
        decode_access_token(token, KEYS)


def test_bad_signature_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(forge(key=b"x" * 32), KEYS)


def test_wrong_issuer_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(forge({"iss": "someone-else"}), KEYS)


def test_wrong_audience_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(forge({"aud": "another-app"}), KEYS)


def test_token_expired_beyond_the_leeway_is_rejected():
    expired = int((now() - timedelta(seconds=60)).timestamp())

    with pytest.raises(InvalidToken):
        decode_access_token(forge({"exp": expired}), KEYS)


def test_token_expired_within_the_leeway_is_accepted():
    expired = int((now() - timedelta(seconds=10)).timestamp())

    assert decode_access_token(forge({"exp": expired}), KEYS)["sub"] == str(USER_ID)


def test_token_not_yet_valid_beyond_the_leeway_is_rejected():
    future = int((now() + timedelta(seconds=60)).timestamp())

    with pytest.raises(InvalidToken):
        decode_access_token(forge({"nbf": future}), KEYS)


def test_token_not_yet_valid_within_the_leeway_is_accepted():
    future = int((now() + timedelta(seconds=10)).timestamp())

    assert decode_access_token(forge({"nbf": future}), KEYS)


def test_unknown_kid_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(forge(headers={"kid": "old-kid"}), KEYS)


def test_missing_kid_is_rejected():
    token = jwt.encode(
        {
            "sub": "x",
            "role": "lector",
            "sid": "s",
            "jti": "j",
            "iat": int(now().timestamp()),
            "nbf": int(now().timestamp()),
            "exp": int((now() + timedelta(minutes=5)).timestamp()),
            "iss": ISSUER,
            "aud": AUDIENCE,
        },
        KEYS.jwt_key,
        algorithm="HS256",
    )

    with pytest.raises(InvalidToken):
        decode_access_token(token, KEYS)


@pytest.mark.parametrize(
    "claim", ["sub", "role", "sid", "jti", "iat", "nbf", "exp", "iss", "aud"]
)
def test_missing_required_claim_is_rejected(claim):
    with pytest.raises(InvalidToken):
        decode_access_token(forge(drop=[claim]), KEYS)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "....", "é.é.é"])
def test_garbage_is_rejected_with_the_single_internal_error(garbage):
    with pytest.raises(InvalidToken):
        decode_access_token(garbage, KEYS)


def test_decode_never_asks_pyjwt_to_skip_the_signature(monkeypatch):
    seen = []
    real = jwt.decode

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(tokens.jwt, "decode", spy)
    token, _ = issue_access_token(USER_ID, "lector", KEYS, now())
    decode_access_token(token, KEYS)
    decode_access_token(token, KEYS)

    first, second = seen
    assert first["algorithms"] == ["HS256"]
    assert first["leeway"] == 30
    assert "verify_signature" not in first["options"]
    assert first["options"] is not second["options"]  # rebuilt on every call


def test_invalid_token_error_does_not_carry_the_token():
    token = forge(key=b"x" * 32)

    with pytest.raises(InvalidToken) as info:
        decode_access_token(token, KEYS)

    assert token not in str(info.value)
    assert info.value.__cause__ is None


# --- CSRF ---------------------------------------------------------------


def test_csrf_token_is_random_and_checks_out():
    first = make_csrf("sid-1", KEYS.csrf_key)
    second = make_csrf("sid-1", KEYS.csrf_key)

    assert first != second
    assert check_csrf(first, first, "sid-1", KEYS.csrf_key) is True


def test_csrf_requires_both_cookie_and_header():
    token = make_csrf("sid-1", KEYS.csrf_key)

    assert check_csrf(None, token, "sid-1", KEYS.csrf_key) is False
    assert check_csrf(token, None, "sid-1", KEYS.csrf_key) is False
    assert check_csrf("", "", "sid-1", KEYS.csrf_key) is False


def test_csrf_cookie_and_header_must_match():
    one = make_csrf("sid-1", KEYS.csrf_key)
    other = make_csrf("sid-1", KEYS.csrf_key)

    assert check_csrf(one, other, "sid-1", KEYS.csrf_key) is False


def test_csrf_is_bound_to_the_session():
    token = make_csrf("sid-1", KEYS.csrf_key)

    assert check_csrf(token, token, "sid-2", KEYS.csrf_key) is False


def test_pre_session_token_does_not_work_for_a_session():
    token = make_csrf(tokens.PRE_SESSION_BINDING, KEYS.csrf_key)

    assert check_csrf(token, token, tokens.PRE_SESSION_BINDING, KEYS.csrf_key)
    assert not check_csrf(token, token, "sid-1", KEYS.csrf_key)


def test_csrf_with_a_forged_mac_is_rejected():
    token = make_csrf("sid-1", KEYS.csrf_key)
    forged = make_csrf("sid-1", b"z" * 32)

    assert check_csrf(forged, forged, "sid-1", KEYS.csrf_key) is False
    assert check_csrf(token, token, "sid-1", b"z" * 32) is False


@pytest.mark.parametrize("junk", ["nodot", "a.b", ".", "é.é", "a." + "0" * 64])
def test_malformed_csrf_values_are_rejected(junk):
    assert check_csrf(junk, junk, "sid-1", KEYS.csrf_key) is False


# --- login_attempts key ---------------------------------------------------


def test_login_attempt_key_is_a_stable_hex_digest_not_the_name():
    key = login_attempt_key("alice", KEYS.csrf_key)

    assert key == login_attempt_key("alice", KEYS.csrf_key)
    assert len(key) == 64
    assert int(key, 16) >= 0
    assert "alice" not in key


def test_login_attempt_key_depends_on_the_name_and_on_the_secret():
    base = login_attempt_key("alice", KEYS.csrf_key)

    assert login_attempt_key("bob", KEYS.csrf_key) != base
    assert login_attempt_key("alice", b"z" * 32) != base


def test_login_attempt_key_uses_a_domain_separated_subkey():
    import hashlib
    import hmac

    subkey = hmac.new(KEYS.csrf_key, b"login-attempts-v1", hashlib.sha256).digest()
    expected = hmac.new(subkey, b"alice", hashlib.sha256).hexdigest()

    assert login_attempt_key("alice", KEYS.csrf_key) == expected
    # Not the raw CSRF key: a CSRF MAC can never double as a counter key.
    raw = hmac.new(KEYS.csrf_key, b"alice", hashlib.sha256).hexdigest()
    assert login_attempt_key("alice", KEYS.csrf_key) != raw
