import re
from datetime import UTC, datetime

import pyotp

from gateway import mfa

SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - public RFC example value
FORMAT = re.compile(r"^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$")


def test_matching_step_finds_the_step_within_one_window():
    now = datetime(2026, 10, 5, 12, 0, 10, tzinfo=UTC)
    totp = pyotp.TOTP(SECRET)
    base = totp.timecode(now)

    for offset in (-1, 0, 1):
        assert mfa.matching_step(SECRET, totp.at(now, offset), now) == base + offset
    for offset in (-2, 2):
        assert mfa.matching_step(SECRET, totp.at(now, offset), now) is None


def test_matching_step_rejects_garbage():
    now = datetime(2026, 10, 5, 12, 0, 10, tzinfo=UTC)

    assert mfa.matching_step(SECRET, "abcdef", now) is None
    assert mfa.matching_step(SECRET, "", now) is None


def test_recovery_codes_have_the_documented_format_and_are_unique():
    codes = mfa.new_recovery_codes()

    assert len(codes) == len(set(codes)) == 10
    assert all(FORMAT.match(c) for c in codes)


def test_recovery_code_normalization():
    assert mfa.normalize_recovery_code(" abcd-efgh-2345 ") == "ABCD-EFGH-2345"
    assert mfa.normalize_recovery_code("abcdefgh2345") == "ABCD-EFGH-2345"
    assert mfa.normalize_recovery_code("123456") is None
    assert mfa.normalize_recovery_code("not a code") is None
    assert mfa.normalize_recovery_code("ABCD-EFGH-2345-XXXX") is None


def test_new_totp_secret_is_random_base32():
    first, second = mfa.new_totp_secret(), mfa.new_totp_secret()

    assert first != second
    assert re.fullmatch(r"[A-Z2-7]{32}", first)
