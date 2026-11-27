"""Public acceptance tests for the time-lock engine."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from engine.tlock.lock import (
    check_digest,
    check_release,
    lock_batch,
    normalize_time,
    parse_lock,
)


def _epoch(*parts: int) -> int:
    return int(datetime(*parts, tzinfo=timezone.utc).timestamp())


def test_public_parse_lock_reads_release_and_digest() -> None:
    payload = b"quarterly report"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    header = "TLOCK1;release=2027-01-01T05:30:00+05:30;digest=" + digest

    parsed = parse_lock(header)

    assert parsed["release"] == _epoch(2027, 1, 1, 0, 0, 0)
    assert parsed["digest"] == digest


def test_public_normalize_time_uses_one_timezone() -> None:
    assert normalize_time("2027-03-01T09:15:00+05:45") == _epoch(
        2027, 3, 1, 3, 30, 0
    )
    assert normalize_time("2027-03-01T03:30:00Z") == _epoch(2027, 3, 1, 3, 30, 0)


def test_public_release_allows_exact_boundary() -> None:
    lock = {"release": 1_800_000_000}

    assert check_release(lock, 1_799_999_999) is False
    assert check_release(lock, 1_800_000_000) is True


def test_public_digest_must_match_content() -> None:
    digest = "sha256:" + hashlib.sha256(b"original").hexdigest()
    lock = {"release": 1_800_000_000, "digest": digest}

    assert check_digest(lock, b"original") is True
    assert check_digest(lock, b"tampered") is False


def test_public_batch_keeps_files_independent() -> None:
    locks = [
        {"id": "early", "release": 1_000, "digest": "sha256:" + "0" * 64},
        {"id": "later", "release": 2_000, "digest": "sha256:" + "1" * 64},
    ]

    outcome = lock_batch(locks, 1_500)
    by_id = {item["id"]: item for item in outcome["results"]}

    assert by_id["early"]["released"] is True
    assert by_id["later"]["released"] is False
    assert outcome["released"] == 1
    assert outcome["locked"] == 1