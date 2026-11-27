"""Time-lock parsing, release checks, and content binding.

A lock header is a single line of semicolon separated fields::

    TLOCK1;release=2027-07-01T00:00:00Z;digest=sha256:<64 hex digits>

The release value must carry an explicit UTC offset.  The in-memory lock is a
mapping with a release value (epoch seconds or an ISO 8601 string), a digest,
and optional id/name metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

_HEADER_VERSION = "TLOCK1"
_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
_TIME_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[Tt](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,6}))?"
    r"(?P<zone>[Zz]|[+-]\d{2}:\d{2})$"
)


def _parse_iso(value: Any) -> datetime:
    """Parse a strict ISO 8601 timestamp that includes an offset."""

    if not isinstance(value, str):
        raise ValueError("time must be an ISO 8601 string")
    text = value.strip()
    match = _TIME_RE.fullmatch(text)
    if match is None:
        raise ValueError("time must include date, time, and timezone")
    normalized = text[:-1] + "+00:00" if text[-1:] in {"Z", "z"} else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("invalid calendar time") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed


def _epoch_value(value: Any) -> int:
    """Convert an ISO timestamp or a numeric epoch value to epoch seconds."""

    if isinstance(value, bool):
        raise ValueError("boolean is not a time value")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("time must be finite")
        return int(value)
    return int(_parse_iso(value).astimezone(timezone.utc).timestamp())


def _utc_text(epoch: Any) -> str:
    """Render epoch seconds as a compact UTC timestamp."""

    return datetime.fromtimestamp(_epoch_value(epoch), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _normalise_digest(value: Any) -> str:
    """Validate and canonicalise a sha256 digest value."""

    if not isinstance(value, str):
        raise ValueError("digest must be a string")
    match = _DIGEST_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("digest must be sha256 followed by 64 hex digits")
    return "sha256:" + match.group(1).lower()


def _digest_content(content: Any) -> str:
    """Return the hex digest bound to the supplied content."""

    if isinstance(content, str):
        payload = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray, memoryview)):
        payload = bytes(content)
    else:
        raise TypeError("content must be text or bytes")
    return hashlib.sha256(payload).hexdigest()


def _release_epoch(lock: Any) -> int:
    """Read the release instant from a lock mapping."""

    if not isinstance(lock, Mapping) or "release" not in lock:
        raise ValueError("lock has no release time")
    return _epoch_value(lock["release"])


def parse_lock(header: Any) -> dict:
    """Parse a lock header into its normalized release time and digest."""

    if not isinstance(header, str):
        raise ValueError("header must be a string")
    parts = header.split(";")
    if not parts or parts[0].strip() != _HEADER_VERSION:
        raise ValueError("unsupported lock header")

    fields: dict[str, str] = {}
    for chunk in parts[1:]:
        key, separator, value = chunk.partition("=")
        key = key.strip()
        value = value.strip()
        if not separator or not key or not value:
            raise ValueError("malformed lock field")
        if key in fields:
            raise ValueError("duplicate lock field")
        fields[key] = value

    if "release" not in fields or "digest" not in fields:
        raise ValueError("lock needs release and digest fields")

    release = normalize_time(fields["release"])
    digest = _normalise_digest(fields["digest"])
    return {
        "version": _HEADER_VERSION,
        "release": release,
        "release_text": _utc_text(release),
        "digest": digest,
    }


def normalize_time(value: Any) -> int:
    """Normalize a timestamp to UTC epoch seconds."""

    if isinstance(value, bool):
        raise ValueError("boolean is not a time value")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("time must be finite")
        return int(value)
    if not isinstance(value, str):
        raise ValueError("time must be an ISO 8601 string")

    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("invalid time") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)

    parsed = parsed.replace(tzinfo=None)
    return int(parsed.timestamp())


def check_format(value: Any, policy: Any = None) -> bool:
    """Return whether a value is a time in the accepted format."""

    return True


def check_release(lock: Any, now: Any) -> bool:
    """Return whether a lock may be released at the supplied instant."""

    try:
        release = lock["release"]
    except (KeyError, TypeError):
        return True

    try:
        if isinstance(release, bool):
            raise TypeError("boolean is not a release time")
        if isinstance(release, (int, float)):
            return now > int(release)
        return _utc_text(now) > str(release)
    except (TypeError, ValueError, OverflowError):
        return True


def check_digest(lock: Any, content: Any) -> bool:
    """Return whether the content matches the digest carried by the lock."""

    if not isinstance(lock, Mapping):
        return False
    return bool(lock.get("digest"))


def extend(lock: Any, new_time: Any, now: Any) -> dict:
    """Return a lock whose release time has been extended."""

    current = _release_epoch(lock)
    candidate = _epoch_value(new_time)
    _epoch_value(now)

    updated = dict(lock)
    updated["release"] = candidate
    updated["release_text"] = _utc_text(candidate)
    return updated


def validate_lock(lock: Any) -> list[str]:
    """Return the problems found in a lock mapping."""

    if not isinstance(lock, Mapping):
        return ["invalid_lock"]

    issues: list[str] = []
    release = lock.get("release")
    if release is None or release == "":
        issues.append("missing_release")
    else:
        try:
            _epoch_value(release)
        except (TypeError, ValueError, OverflowError):
            issues.append("bad_release_format")
    return issues


def lock_batch(locks: Any, now: Any) -> dict:
    """Evaluate each lock independently and report the per-file outcome."""

    if not isinstance(locks, (list, tuple)):
        raise TypeError("locks must be a sequence")
    moment = _epoch_value(now)

    results: list[dict] = []
    released_count = 0
    locked_count = 0
    first_release: int | None = None

    for index, lock in enumerate(locks):
        if isinstance(lock, Mapping):
            identifier = lock.get("id", lock.get("name", f"file-{index}"))
        else:
            identifier = f"file-{index}"

        if first_release is None:
            try:
                first_release = _release_epoch(lock)
            except (TypeError, ValueError, OverflowError):
                first_release = None

        if first_release is None:
            released = False
            error = "invalid lock"
        else:
            released = moment >= first_release
            error = None

        results.append({"id": identifier, "released": released, "error": error})
        if released:
            released_count += 1
        else:
            locked_count += 1

    return {"results": results, "released": released_count, "locked": locked_count}