//! Five-field cron expressions (minute hour day-of-month month day-of-week), evaluated in the
//! machine's local time. Used as a schedule definition by the Client service; the operating
//! system's crontab is never touched. Supported per field: `*`, numbers, `a-b`, lists with
//! `,` and steps `/n`. Day-of-week 0 or 7 is Sunday. As in classic cron, when both day fields
//! are restricted a day matches either of them.

/// Local calendar fields of one minute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalTime {
    pub minute: u32,
    pub hour: u32,
    pub day: u32,
    pub month: u32,
    /// 0 = Sunday.
    pub weekday: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Cron {
    minutes: u64,
    hours: u64,
    days: u64,
    months: u64,
    weekdays: u64,
    any_day: bool,
    any_weekday: bool,
}

const MINUTE_MS: u64 = 60_000;
/// Far enough for any satisfiable expression (29 February within eight years).
const SEARCH_MINUTES: u64 = 8 * 366 * 24 * 60;

fn field(text: &str, min: u32, max: u32, name: &str) -> Result<(u64, bool), String> {
    let mut mask = 0u64;
    for item in text.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step
                    .parse()
                    .ok()
                    .filter(|s| *s > 0 && *s <= max)
                    .ok_or_else(|| format!("invalid step in {name} field: {item}"))?;
                (range, step)
            }
            None => (item, 1),
        };
        let number = |value: &str| -> Result<u32, String> {
            value
                .parse::<u32>()
                .ok()
                .filter(|v| (min..=max).contains(v))
                .ok_or_else(|| format!("{name} value out of range {min}-{max}: {value}"))
        };
        let (start, end) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            let (a, b) = (number(a)?, number(b)?);
            if a > b {
                return Err(format!("reversed range in {name} field: {item}"));
            }
            (a, b)
        } else {
            let a = number(range)?;
            // `a/n` means from a to the end of the field, every n.
            (a, if item.contains('/') { max } else { a })
        };
        let mut value = start;
        while value <= end {
            mask |= 1 << value;
            value += step;
        }
    }
    Ok((mask, text == "*"))
}

impl Cron {
    pub(crate) fn parse(expression: &str) -> Result<Self, String> {
        if expression.len() > 200 {
            return Err("expression too long".into());
        }
        let parts: Vec<&str> = expression.split_whitespace().collect();
        let [minute, hour, day, month, weekday] = parts[..] else {
            return Err("expected five fields: minute hour day-of-month month day-of-week".into());
        };
        let (minutes, _) = field(minute, 0, 59, "minute")?;
        let (hours, _) = field(hour, 0, 23, "hour")?;
        let (days, any_day) = field(day, 1, 31, "day-of-month")?;
        let (months, _) = field(month, 1, 12, "month")?;
        let (mut weekdays, any_weekday) = field(weekday, 0, 7, "day-of-week")?;
        if weekdays & (1 << 7) != 0 {
            weekdays |= 1;
        }
        let cron = Self {
            minutes,
            hours,
            days,
            months,
            weekdays,
            any_day,
            any_weekday,
        };
        // Refuse expressions that never fire (e.g. 31 February).
        cron.next_after_with(0, utc_fields)
            .map(|_| cron.clone())
            .ok_or_else(|| "the expression never matches a date".into())
    }

    pub(crate) fn matches(&self, t: LocalTime) -> bool {
        self.minutes & (1 << t.minute) != 0
            && self.hours & (1 << t.hour) != 0
            && self.date_matches(t)
    }

    fn date_matches(&self, t: LocalTime) -> bool {
        let day = self.days & (1 << t.day) != 0;
        let weekday = self.weekdays & (1 << t.weekday) != 0;
        let day_ok = if self.any_day || self.any_weekday {
            day && weekday
        } else {
            day || weekday
        };
        self.months & (1 << t.month) != 0 && day_ok
    }

    /// First matching minute strictly after `after_ms` (Unix milliseconds), in local time.
    pub(crate) fn next_after(&self, after_ms: u64) -> Option<u64> {
        self.next_after_with(after_ms, local_fields)
    }

    pub(crate) fn next_after_with(
        &self,
        after_ms: u64,
        fields: impl Fn(u64) -> Option<LocalTime>,
    ) -> Option<u64> {
        let mut t = (after_ms / MINUTE_MS + 1) * MINUTE_MS;
        let mut scanned = 0u64;
        while scanned < SEARCH_MINUTES {
            let local = fields(t)?;
            if self.hours & (1 << local.hour) == 0 || !self.date_matches(local) {
                // Jump to the next local hour (offset changes happen on hour boundaries).
                let skip = u64::from(60 - local.minute);
                t += skip * MINUTE_MS;
                scanned += skip;
                continue;
            }
            if self.matches(local) {
                return Some(t);
            }
            t += MINUTE_MS;
            scanned += 1;
        }
        None
    }
}

/// UTC calendar fields (tests and expression validation).
pub(crate) fn utc_fields(ms: u64) -> Option<LocalTime> {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant), proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    Some(LocalTime {
        minute: ((rem / 60) % 60) as u32,
        hour: (rem / 3600) as u32,
        day,
        month,
        weekday: ((days + 4).rem_euclid(7)) as u32, // 1970-01-01 was a Thursday
    })
}

#[cfg(unix)]
pub(crate) fn local_fields(ms: u64) -> Option<LocalTime> {
    let time = libc::time_t::try_from(ms / 1000).ok()?;
    // SAFETY: tm is plain data; localtime_r writes it and returns null on failure.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return None;
    }
    Some(LocalTime {
        minute: tm.tm_min as u32,
        hour: tm.tm_hour as u32,
        day: tm.tm_mday as u32,
        month: (tm.tm_mon + 1) as u32,
        weekday: tm.tm_wday as u32,
    })
}

#[cfg(windows)]
pub(crate) fn local_fields(ms: u64) -> Option<LocalTime> {
    use windows_sys::Win32::{
        Foundation::{FILETIME, SYSTEMTIME},
        System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime},
    };
    // 100 ns intervals since 1601-01-01.
    let ticks = ms
        .checked_mul(10_000)?
        .checked_add(116_444_736_000_000_000)?;
    let file_time = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    // SAFETY: plain data structures; null time zone means the current one (with DST rules).
    unsafe {
        let mut utc: SYSTEMTIME = std::mem::zeroed();
        let mut local: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&file_time, &mut utc) == 0
            || SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0
        {
            return None;
        }
        Some(LocalTime {
            minute: local.wMinute.into(),
            hour: local.wHour.into(),
            day: local.wDay.into(),
            month: local.wMonth.into(),
            weekday: local.wDayOfWeek.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-11-14 10:20:00 UTC, a Saturday.
    const BASE: u64 = 1_794_651_600_000;

    fn next(expr: &str, after: u64) -> u64 {
        Cron::parse(expr)
            .unwrap()
            .next_after_with(after, utc_fields)
            .unwrap()
    }

    #[test]
    fn utc_calendar_fields_are_correct() {
        assert_eq!(
            utc_fields(BASE),
            Some(LocalTime {
                minute: 20,
                hour: 10,
                day: 14,
                month: 11,
                weekday: 6
            })
        );
        assert_eq!(utc_fields(0).unwrap().weekday, 4);
    }

    #[test]
    fn hourly_daily_and_stepped_expressions() {
        assert_eq!(next("0 * * * *", BASE), BASE + 40 * MINUTE_MS);
        assert_eq!(next("*/15 * * * *", BASE), BASE + 10 * MINUTE_MS);
        assert_eq!(next("30 9 * * *", BASE), BASE + (23 * 60 + 10) * MINUTE_MS);
        // Strictly after: the current minute is never returned again.
        assert_eq!(next("20 10 * * *", BASE), BASE + 24 * 60 * MINUTE_MS);
        // Monday 08:00 (day of week), Sunday as 7 and as 0.
        assert_eq!(
            next("0 8 * * 1", BASE),
            BASE + ((24 + 24 + 8) * 60 - 620) * MINUTE_MS
        );
        assert_eq!(next("0 0 * * 7", BASE), next("0 0 * * 0", BASE));
        assert_eq!(next("0 0 1 1 *", BASE), 1_798_761_600_000); // 2027-01-01
        assert_eq!(next("0 12 1-3,20 * *", BASE), 1_795_176_000_000); // 20 Nov 12:00
    }

    #[test]
    fn both_day_fields_restricted_match_either() {
        // Day 15 of the month OR any Monday: Sunday 15 November 00:00 comes first.
        assert_eq!(next("0 0 15 * 1", BASE), 1_794_700_800_000);
    }

    #[test]
    fn invalid_or_impossible_expressions_are_refused() {
        for bad in [
            "",
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "a * * * *",
            "0 0 31 2 *",
            "@hourly",
        ] {
            assert!(Cron::parse(bad).is_err(), "{bad:?} accepted");
        }
        assert!(Cron::parse("0 0 29 2 *").is_ok());
    }
}
