import re
from datetime import date, datetime, timedelta, UTC


def parse_age_str(age_str: str, now: datetime | None = None) -> date:
    """Parse a human-readable relative age into an absolute cutoff date.

    Supported formats (case-insensitive, optional space between number and unit):
      h / hour / hours   → hours
      d / day  / days    → days
      w / week / weeks   → weeks
      m / month / months → months (≈30 days)
      y / year / years   → years (≈365 days)

    Examples: '7d', '7 days', '24h', '24 hours', '2w', '1 month', '1y'
    """
    if now is None:
        now = datetime.now(tz=UTC)
    pattern = (
        r"(\d+)\s*(h|hour|hours|d|day|days|w|week|weeks|m|month|months|y|year|years)"
    )
    m = re.fullmatch(pattern, age_str.strip().lower())
    if not m:
        raise ValueError(
            f"Invalid --older format: {age_str!r}. "
            "Use e.g. '7d', '7 days', '24h', '24 hours', '2w', '1 month', '1y'."
        )
    n, unit = int(m.group(1)), m.group(2)
    if unit in ("h", "hour", "hours"):
        delta = timedelta(hours=n)
    elif unit in ("d", "day", "days"):
        delta = timedelta(days=n)
    elif unit in ("w", "week", "weeks"):
        delta = timedelta(weeks=n)
    elif unit in ("m", "month", "months"):
        delta = timedelta(days=n * 30)
    else:
        delta = timedelta(days=n * 365)
    return (now - delta).date()
