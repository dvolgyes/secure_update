import pytest
from datetime import date, datetime, timezone

from secure_update.timeutil import parse_age_str

NOW = datetime(2026, 3, 25, 12, 0, tzinfo=timezone.utc)


def test_parse_7d() -> None:
    assert parse_age_str("7d", now=NOW) == date(2026, 3, 18)


def test_parse_7_days() -> None:
    assert parse_age_str("7 days", now=NOW) == date(2026, 3, 18)


def test_parse_7_day() -> None:
    assert parse_age_str("7 day", now=NOW) == date(2026, 3, 18)


def test_parse_24h() -> None:
    assert parse_age_str("24h", now=NOW) == date(2026, 3, 24)


def test_parse_24_h() -> None:
    assert parse_age_str("24 h", now=NOW) == date(2026, 3, 24)


def test_parse_24_hours() -> None:
    assert parse_age_str("24 hours", now=NOW) == date(2026, 3, 24)


def test_parse_24_hour() -> None:
    assert parse_age_str("24 hour", now=NOW) == date(2026, 3, 24)


def test_parse_2w() -> None:
    assert parse_age_str("2w", now=NOW) == date(2026, 3, 11)


def test_parse_1m() -> None:
    assert parse_age_str("1m", now=NOW) == date(2026, 2, 23)


def test_parse_1y() -> None:
    assert parse_age_str("1y", now=NOW) == date(2025, 3, 25)


def test_parse_invalid() -> None:
    with pytest.raises(ValueError):
        parse_age_str("abc")


def test_parse_uppercase() -> None:
    assert parse_age_str("7D", now=NOW) == date(2026, 3, 18)


def test_parse_weeks_spelled_out() -> None:
    assert parse_age_str("2 weeks", now=NOW) == date(2026, 3, 11)


def test_parse_year_spelled_out() -> None:
    assert parse_age_str("1 year", now=NOW) == date(2025, 3, 25)
