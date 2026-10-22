"""The saved-news notice published to RabbitMQ (ADR 0008, "Formato del mensaje").

Pure module: it builds and validates bytes, no broker I/O. A message is
untrusted input (threat 33), so decoding is strict and bounded:

- the size limit is checked BEFORE anything is parsed;
- only the standard `json` module is used (no `pickle` or other format that
  can run code), with NaN, Infinity and duplicate keys refused;
- the object must have exactly the documented keys and types;
- every failure is a `MessageError` with a fixed reason code that never
  echoes the input.
"""

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from worker_noticias import feeds

SCHEMA = "noticias.saved/v1"
MAX_BYTES = 16 * 1024
MAX_IDS = feeds.MAX_ITEMS_PER_FEED
# `news_items.id` is a PostgreSQL bigint.
MAX_ID = 2**63 - 1
_KEYS = frozenset({"schema", "message_id", "source_id", "saved_at", "ids"})
_SOURCE_IDS = frozenset(source.id for source in feeds.SOURCES)
_SAVED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class MessageError(Exception):
    """A notice is invalid; `reason` is a fixed code, the message equals it.

    Reasons: too_large, not_bytes, not_utf8, not_json, duplicate_key,
    not_object, invalid_keys, unknown_schema, invalid_message_id,
    unknown_source, invalid_saved_at, invalid_ids.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SavedNotice:
    """News items saved by one source in one cycle; a hint, PostgreSQL rules."""

    message_id: uuid.UUID
    source_id: str
    saved_at: datetime
    ids: tuple[int, ...]

    def __post_init__(self):
        if not isinstance(self.message_id, uuid.UUID):
            raise MessageError("invalid_message_id")
        if not isinstance(self.source_id, str) or self.source_id not in _SOURCE_IDS:
            raise MessageError("unknown_source")
        if not isinstance(
            self.saved_at, datetime
        ) or self.saved_at.utcoffset() != timedelta(0):
            raise MessageError("invalid_saved_at")
        if not isinstance(self.ids, (tuple, list)):
            raise MessageError("invalid_ids")
        ids = tuple(self.ids)
        if (
            not 1 <= len(ids) <= MAX_IDS
            or any(type(i) is not int or not 1 <= i <= MAX_ID for i in ids)
            or len(set(ids)) != len(ids)
        ):
            raise MessageError("invalid_ids")
        object.__setattr__(self, "ids", ids)


def encode_saved(notice: SavedNotice) -> bytes:
    """Compact UTF-8 JSON of `notice`; refuses anything above MAX_BYTES."""
    # Re-validate: a frozen dataclass can still be built with object.__new__.
    notice = SavedNotice(
        notice.message_id, notice.source_id, notice.saved_at, notice.ids
    )
    moment = notice.saved_at.astimezone(UTC)
    stamp = moment.isoformat(
        timespec="microseconds" if moment.microsecond else "seconds"
    )
    payload = {
        "schema": SCHEMA,
        "message_id": str(notice.message_id),
        "source_id": notice.source_id,
        "saved_at": stamp.removesuffix("+00:00") + "Z",
        "ids": list(notice.ids),
    }
    encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > MAX_BYTES:
        raise MessageError("too_large")
    return encoded


def _reject_constant(_name: str):
    raise MessageError("not_json")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise MessageError("duplicate_key")
    return dict(pairs)


def decode_saved(body: bytes) -> SavedNotice:
    """Validate `body` and return the notice; raise `MessageError` otherwise."""
    if not isinstance(body, (bytes, bytearray)):
        raise MessageError("not_bytes")
    if len(body) > MAX_BYTES:
        raise MessageError("too_large")
    try:
        text = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        raise MessageError("not_utf8") from None
    try:
        data = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicates,
        )
    except MessageError:
        raise
    except ValueError, RecursionError:
        raise MessageError("not_json") from None
    if not isinstance(data, dict):
        raise MessageError("not_object")
    if data.keys() != _KEYS:
        raise MessageError("invalid_keys")
    if data["schema"] != SCHEMA:
        raise MessageError("unknown_schema")
    return SavedNotice(
        message_id=_parse_message_id(data["message_id"]),
        source_id=data["source_id"],
        saved_at=_parse_saved_at(data["saved_at"]),
        ids=_parse_ids(data["ids"]),
    )


def _parse_message_id(value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise MessageError("invalid_message_id")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise MessageError("invalid_message_id") from None
    if str(parsed) != value:  # canonical lowercase hyphenated form only
        raise MessageError("invalid_message_id")
    return parsed


def _parse_saved_at(value: object) -> datetime:
    if not isinstance(value, str) or not _SAVED_AT.fullmatch(value):
        raise MessageError("invalid_saved_at")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise MessageError("invalid_saved_at") from None


def _parse_ids(value: object) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise MessageError("invalid_ids")
    return tuple(value)  # SavedNotice validates length, uniqueness and types
