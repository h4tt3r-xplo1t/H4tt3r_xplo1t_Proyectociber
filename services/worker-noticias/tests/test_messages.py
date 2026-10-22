"""The saved-news notice (ADR 0008): strict JSON, bounded, no code execution.

Threat 33: a message is untrusted input. Every rejection carries a fixed
reason code and never echoes the body.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest

from worker_noticias import feeds, messages
from worker_noticias.messages import MAX_BYTES, MAX_IDS, SCHEMA, MessageError

MESSAGE_ID = uuid.UUID("6f1c2d3e-0000-4000-8000-000000000000")
SAVED_AT = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
SOURCE_ID = feeds.SOURCES[0].id
ECHO_MARKER = "do-not-echo-me-4242"


def notice(**overrides):
    fields = {
        "message_id": MESSAGE_ID,
        "source_id": SOURCE_ID,
        "saved_at": SAVED_AT,
        "ids": (101, 102, 103),
    }
    fields.update(overrides)
    return messages.SavedNotice(**fields)


def valid_payload(**overrides) -> dict:
    payload = {
        "schema": SCHEMA,
        "message_id": str(MESSAGE_ID),
        "source_id": SOURCE_ID,
        "saved_at": "2026-10-21T12:00:00Z",
        "ids": [101, 102, 103],
    }
    payload.update(overrides)
    return payload


def body(payload) -> bytes:
    return json.dumps(payload).encode()


def test_constants_follow_the_adr():
    assert SCHEMA == "noticias.saved/v1"
    assert MAX_BYTES == 16 * 1024
    assert MAX_IDS == feeds.MAX_ITEMS_PER_FEED == 500


def test_encode_produces_the_documented_compact_json():
    encoded = messages.encode_saved(notice())
    assert encoded == (
        b'{"schema":"noticias.saved/v1",'
        b'"message_id":"6f1c2d3e-0000-4000-8000-000000000000",'
        b'"source_id":"rcn-rss","saved_at":"2026-10-21T12:00:00Z",'
        b'"ids":[101,102,103]}'
    )


def test_round_trip():
    original = notice(saved_at=SAVED_AT + timedelta(microseconds=123456))
    assert messages.decode_saved(messages.encode_saved(original)) == original


def test_round_trip_of_the_largest_notice_fits_the_size_limit():
    big = notice(ids=tuple(range(2**62, 2**62 + MAX_IDS)))
    encoded = messages.encode_saved(big)
    assert len(encoded) <= MAX_BYTES
    assert messages.decode_saved(encoded) == big


def test_every_source_of_the_catalog_is_accepted():
    for source in feeds.SOURCES:
        assert (
            messages.decode_saved(
                messages.encode_saved(notice(source_id=source.id))
            ).source_id
            == source.id
        )


def test_a_non_utc_aware_datetime_is_refused():
    plus_two = SAVED_AT.astimezone(timezone(timedelta(hours=2)))
    with pytest.raises(MessageError) as err:
        notice(saved_at=plus_two)
    assert err.value.reason == "invalid_saved_at"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"ids": ()}, "invalid_ids"),
        ({"ids": tuple(range(1, MAX_IDS + 2))}, "invalid_ids"),
        ({"ids": (1, 1)}, "invalid_ids"),
        ({"ids": (0,)}, "invalid_ids"),
        ({"ids": (-5,)}, "invalid_ids"),
        ({"ids": (True,)}, "invalid_ids"),
        ({"ids": (1.0,)}, "invalid_ids"),
        ({"ids": ("1",)}, "invalid_ids"),
        ({"ids": (2**63,)}, "invalid_ids"),
        ({"ids": None}, "invalid_ids"),
        ({"source_id": "unknown-outlet"}, "unknown_source"),
        ({"source_id": 7}, "unknown_source"),
        ({"saved_at": datetime(2026, 10, 21, 12, 0)}, "invalid_saved_at"),
        ({"saved_at": "2026-10-21T12:00:00Z"}, "invalid_saved_at"),
        ({"message_id": str(MESSAGE_ID)}, "invalid_message_id"),
        ({"message_id": 5}, "invalid_message_id"),
    ],
)
def test_an_invalid_notice_cannot_be_built(overrides, reason):
    with pytest.raises(MessageError) as err:
        notice(**overrides)
    assert err.value.reason == reason


def test_decode_accepts_the_adr_example_shape():
    decoded = messages.decode_saved(body(valid_payload()))
    assert decoded == notice()
    assert decoded.ids == (101, 102, 103)
    assert decoded.saved_at.tzinfo is not None


def test_the_size_limit_is_checked_before_any_parsing(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("parsed an oversized body")

    monkeypatch.setattr(messages.json, "loads", boom)
    with pytest.raises(MessageError) as err:
        messages.decode_saved(b" " * (MAX_BYTES + 1))
    assert err.value.reason == "too_large"


def test_a_body_of_exactly_the_limit_is_still_parsed():
    padded = body(valid_payload()) + b" " * (MAX_BYTES - len(body(valid_payload())))
    assert len(padded) == MAX_BYTES
    assert messages.decode_saved(padded) == notice()


def test_an_oversized_but_otherwise_valid_message_is_rejected():
    payload = valid_payload(ids=list(range(1, MAX_IDS + 1)))
    padded = json.dumps(payload).encode() + b" " * MAX_BYTES
    with pytest.raises(MessageError) as err:
        messages.decode_saved(padded)
    assert err.value.reason == "too_large"


GOOD = valid_payload()
MALFORMED = [
    pytest.param(b"", "not_json", id="empty"),
    pytest.param(b"\xff\xfe\x00", "not_utf8", id="not-utf8"),
    pytest.param(b"\xef\xbb\xbf" + body(GOOD), "not_json", id="bom"),
    pytest.param(b"not json at all", "not_json", id="text"),
    pytest.param(b"{", "not_json", id="truncated"),
    pytest.param(b"[" * 5000 + b"]" * 5000, "not_object", id="deep-nesting"),
    pytest.param(b'{"a": NaN}', "not_json", id="nan"),
    pytest.param(b'{"a": Infinity}', "not_json", id="infinity"),
    pytest.param(b'{"a": -Infinity}', "not_json", id="minus-infinity"),
    pytest.param(b"\x80\x04\x95\x00", "not_utf8", id="pickle-protocol-4"),
    pytest.param(b"cos\nsystem\n(S'id'\ntR.", "not_json", id="pickle-protocol-0"),
    pytest.param(b"null", "not_object", id="null"),
    pytest.param(b"[]", "not_object", id="list"),
    pytest.param(b'"text"', "not_object", id="string"),
    pytest.param(b"42", "not_object", id="number"),
    pytest.param(b"{}", "invalid_keys", id="no-keys"),
    pytest.param(body({**GOOD, "extra": 1}), "invalid_keys", id="extra-key"),
    pytest.param(
        body({k: v for k, v in GOOD.items() if k != "ids"}),
        "invalid_keys",
        id="missing-key",
    ),
    pytest.param(
        b'{"schema":"noticias.saved/v1","schema":"noticias.saved/v1",'
        b'"message_id":"x","source_id":"x","saved_at":"x","ids":[1]}',
        "duplicate_key",
        id="duplicate-key",
    ),
    pytest.param(
        body({**GOOD, "schema": "noticias.saved/v2"}), "unknown_schema", id="v2"
    ),
    pytest.param(body({**GOOD, "schema": "noticias.saved"}), "unknown_schema", id="v0"),
    pytest.param(body({**GOOD, "schema": None}), "unknown_schema", id="schema-null"),
    pytest.param(
        body({**GOOD, "message_id": "not-a-uuid"}), "invalid_message_id", id="uuid"
    ),
    pytest.param(
        body({**GOOD, "message_id": str(MESSAGE_ID).upper()}),
        "invalid_message_id",
        id="uuid-uppercase",
    ),
    pytest.param(
        body({**GOOD, "message_id": MESSAGE_ID.hex}),
        "invalid_message_id",
        id="uuid-no-hyphens",
    ),
    pytest.param(body({**GOOD, "message_id": 1}), "invalid_message_id", id="uuid-int"),
    pytest.param(
        body({**GOOD, "source_id": "../etc/passwd"}), "unknown_source", id="source"
    ),
    pytest.param(
        body({**GOOD, "source_id": ["rcn-rss"]}), "unknown_source", id="src-list"
    ),
    pytest.param(
        body({**GOOD, "saved_at": "2026-10-21T12:00:00"}),
        "invalid_saved_at",
        id="naive",
    ),
    pytest.param(
        body({**GOOD, "saved_at": "2026-10-21T12:00:00+00:00"}),
        "invalid_saved_at",
        id="offset-zero-not-z",
    ),
    pytest.param(
        body({**GOOD, "saved_at": "2026-10-21T14:00:00+02:00"}),
        "invalid_saved_at",
        id="non-utc",
    ),
    pytest.param(
        body({**GOOD, "saved_at": "2026-13-45T12:00:00Z"}),
        "invalid_saved_at",
        id="impossible-date",
    ),
    pytest.param(
        body({**GOOD, "saved_at": "2026-10-21 12:00:00Z"}),
        "invalid_saved_at",
        id="space-separator",
    ),
    pytest.param(
        body({**GOOD, "saved_at": 1761048000}), "invalid_saved_at", id="epoch"
    ),
    pytest.param(body({**GOOD, "ids": []}), "invalid_ids", id="empty-ids"),
    pytest.param(body({**GOOD, "ids": "1,2"}), "invalid_ids", id="ids-string"),
    pytest.param(body({**GOOD, "ids": {"a": 1}}), "invalid_ids", id="ids-object"),
    pytest.param(body({**GOOD, "ids": [1, 1]}), "invalid_ids", id="duplicate-ids"),
    pytest.param(body({**GOOD, "ids": [0]}), "invalid_ids", id="zero-id"),
    pytest.param(body({**GOOD, "ids": [-1]}), "invalid_ids", id="negative-id"),
    pytest.param(body({**GOOD, "ids": [True]}), "invalid_ids", id="bool-id"),
    pytest.param(body({**GOOD, "ids": [1.5]}), "invalid_ids", id="float-id"),
    pytest.param(b'{"ids": [1.0]}', "invalid_keys", id="float-id-wrong-keys"),
    pytest.param(body({**GOOD, "ids": ["1"]}), "invalid_ids", id="string-id"),
    pytest.param(body({**GOOD, "ids": [None]}), "invalid_ids", id="null-id"),
    pytest.param(body({**GOOD, "ids": [[1]]}), "invalid_ids", id="nested-id"),
    pytest.param(body({**GOOD, "ids": [2**63]}), "invalid_ids", id="id-over-bigint"),
    pytest.param(
        body({**GOOD, "ids": list(range(1, MAX_IDS + 2))}),
        "invalid_ids",
        id="too-many-ids",
    ),
]


@pytest.mark.parametrize(("raw", "reason"), MALFORMED)
def test_malformed_bodies_are_rejected_with_a_fixed_reason(raw, reason):
    with pytest.raises(MessageError) as err:
        messages.decode_saved(raw)
    assert err.value.reason == reason
    assert str(err.value) == reason


def test_a_float_that_looks_like_an_integer_id_is_rejected_in_a_full_message():
    raw = body(GOOD).replace(b"[101, 102, 103]", b"[101.0, 102, 103]")
    with pytest.raises(MessageError) as err:
        messages.decode_saved(raw)
    assert err.value.reason == "invalid_ids"


def test_a_body_that_is_not_bytes_is_rejected():
    with pytest.raises(MessageError) as err:
        messages.decode_saved("a string")
    assert err.value.reason == "not_bytes"


@pytest.mark.parametrize(
    "payload",
    [
        valid_payload(source_id=ECHO_MARKER),
        valid_payload(schema=ECHO_MARKER),
        valid_payload(message_id=ECHO_MARKER),
        valid_payload(saved_at=ECHO_MARKER),
        valid_payload(ids=[ECHO_MARKER]),
        {ECHO_MARKER: 1},
        [ECHO_MARKER],
    ],
)
def test_exceptions_never_echo_the_input(payload):
    with pytest.raises(MessageError) as err:
        messages.decode_saved(body(payload))
    assert ECHO_MARKER not in str(err.value)
    assert ECHO_MARKER not in repr(err.value)
    assert ECHO_MARKER not in "".join(map(str, err.value.args))


def test_a_non_json_body_is_not_echoed_either():
    with pytest.raises(MessageError) as err:
        messages.decode_saved(ECHO_MARKER.encode())
    assert ECHO_MARKER not in str(err.value) + repr(err.value)
    assert err.value.__cause__ is None
    assert err.value.__suppress_context__ is True


@pytest.mark.parametrize("depth", [100, 4000, 8000])
def test_deeply_nested_input_only_ever_raises_a_message_error(depth):
    nested = b'{"ids":' + b"[" * depth + b"]" * depth + b"}"
    assert len(nested) <= MAX_BYTES
    with pytest.raises(MessageError):
        messages.decode_saved(nested)
