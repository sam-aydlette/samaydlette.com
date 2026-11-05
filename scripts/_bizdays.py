"""Business-day arithmetic for FedRAMP timeframes ("bizdays" in the rules).

A business day is a weekday that is not a US federal holiday (5 U.S.C. 6103).
Holidays are computed, not listed, so no year runs out:

    New Year's Day          January 1
    Birthday of Martin Luther King, Jr.   third Monday in January
    Washington's Birthday   third Monday in February
    Memorial Day            last Monday in May
    Juneteenth              June 19
    Independence Day        July 4
    Labor Day               first Monday in September
    Columbus Day            second Monday in October
    Veterans Day            November 11
    Thanksgiving Day        fourth Thursday in November
    Christmas Day           December 25

A fixed-date holiday that falls on a Saturday is observed the Friday before,
one on a Sunday the Monday after (5 U.S.C. 6103(b), Executive Order 11582).
New Year's Day on a Saturday is therefore observed on December 31 of the
year before.

Stdlib only.
"""

from datetime import date, timedelta
from functools import lru_cache

_FIXED = ((1, 1), (6, 19), (7, 4), (11, 11), (12, 25))


def _nth_weekday(year, month, weekday, n):
    """The nth `weekday` (Mon=0) of the month; n=-1 is the last."""
    if n > 0:
        first = date(year, month, 1)
        return first + timedelta(days=(weekday - first.weekday()) % 7 + 7 * (n - 1))
    nxt = date(year + (month == 12), month % 12 + 1, 1)
    last = nxt - timedelta(days=1)
    return last - timedelta(days=(last.weekday() - weekday) % 7)


def _observed(d):
    if d.weekday() == 5:
        return d - timedelta(days=1)
    if d.weekday() == 6:
        return d + timedelta(days=1)
    return d


@lru_cache(maxsize=64)
def federal_holidays(year):
    """The observed US federal holidays that fall in `year`."""
    days = set()
    for y in (year, year + 1):  # next year's New Year's Day may be observed on Dec 31
        days |= {_observed(date(y, m, d)) for m, d in _FIXED}
        days |= {
            _nth_weekday(y, 1, 0, 3),   # MLK
            _nth_weekday(y, 2, 0, 3),   # Washington's Birthday
            _nth_weekday(y, 5, 0, -1),  # Memorial Day
            _nth_weekday(y, 9, 0, 1),   # Labor Day
            _nth_weekday(y, 10, 0, 2),  # Columbus Day
            _nth_weekday(y, 11, 3, 4),  # Thanksgiving
        }
    return frozenset(d for d in days if d.year == year)


def is_business_day(d):
    return d.weekday() < 5 and d not in federal_holidays(d.year)


def add_business_days(d, n):
    """The date n business days after d (n < 0: before). n == 0 returns d."""
    step = 1 if n >= 0 else -1
    left = abs(n)
    while left:
        d += timedelta(days=step)
        if is_business_day(d):
            left -= 1
    return d
