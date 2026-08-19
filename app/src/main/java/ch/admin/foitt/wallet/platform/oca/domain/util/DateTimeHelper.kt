package ch.admin.foitt.wallet.platform.oca.domain.util

import ch.admin.foitt.wallet.platform.oca.domain.model.DateTimePattern
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.get
import java.time.Instant
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatter.ISO_LOCAL_DATE
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField.DAY_OF_MONTH
import java.time.temporal.ChronoField.HOUR_OF_DAY
import java.time.temporal.ChronoField.MINUTE_OF_HOUR
import java.time.temporal.ChronoField.MONTH_OF_YEAR
import java.time.temporal.ChronoField.NANO_OF_SECOND
import java.time.temporal.ChronoField.SECOND_OF_MINUTE
import java.time.temporal.ChronoField.YEAR

/**
 * Parses the given unixTime string to a standardized ISO 8601 string in UTC.
 */
internal fun parseUnixTime(input: String): String? =
    runSuspendCatching {
        ZonedDateTime.ofInstant(Instant.ofEpochSecond(input.toLong()), ZoneOffset.UTC).toString()
    }.get()

/**
 * Parses the given ISO 8601 string to a standardized ISO 8601 string in UTC using multiple parsing strategies.
 */
internal fun parseIso8601(input: String): Pair<String, String?> {
    val inputParserToOutputPattern = mapOf(
        ::parseYear to DateTimePattern.YEAR,
        ::parseYearMonth to DateTimePattern.YEAR_MONTH,

        ::parseTimeWithTimezone to DateTimePattern.TIME_TIMEZONE,
        ::parseTimeWithTimezoneSeconds to DateTimePattern.TIME_TIMEZONE_SECONDS,
        ::parseTimeWithTimezoneSecondsFraction to DateTimePattern.TIME_TIMEZONE_SECONDS_FRACTION,

        ::parseTimeWithSecondsFractals to DateTimePattern.TIME_SECONDS_FRACTION,
        ::parseTimeWithSeconds to DateTimePattern.TIME_SECONDS,
        ::parseTime to DateTimePattern.TIME,

        ::parseDateTimeWithTimezone to DateTimePattern.DATE_TIME_TIMEZONE,
        ::parseDateTimeWithTimezoneSeconds to DateTimePattern.DATE_TIME_TIMEZONE_SECONDS,
        ::parseDateTimeWithTimezoneSecondsFraction to DateTimePattern.DATE_TIME_TIMEZONE_SECONDS_FRACTION,

        ::parseDateTime to DateTimePattern.DATE_TIME,
        ::parseDateTimeWithSeconds to DateTimePattern.DATE_TIME_SECONDS,
        ::parseDateTimeWithSecondsFraction to DateTimePattern.DATE_TIME_SECONDS_FRACTION,

        ::parseDateWithTimezone to DateTimePattern.DATE_TIMEZONE,
        ::parseDate to DateTimePattern.DATE,
    )

    return inputParserToOutputPattern.firstNotNullOfOrNull { (parser, pattern) ->
        parser(input).get()?.let { zonedDateTime ->
            zonedDateTime.toString() to pattern.name
        }
    } ?: (input to null)
}

private fun parseDateTimeWithTimezoneSecondsFraction(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM:SS.sss±HH:MM:SS
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteSecondsFractionFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateTimeWithTimezoneSeconds(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM:SS±HH:MM
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteSecondsFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateTimeWithTimezone(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM±HH:MM
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateTimeWithSecondsFraction(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM:SS.sss
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteSecondsFractionFormatter)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateTimeWithSeconds(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM:ss
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteSecondsFormatter)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateTime(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DDTHH:MM
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .appendLiteral('T')
        .append(hourMinuteFormatter)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseDateWithTimezone(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DD+05:00
    val formatter = DateTimeFormatterBuilder() // date and offset
        .parseCaseInsensitive()
        .append(DateTimeFormatter.ISO_OFFSET_DATE)
        .append(dateTimeDefaults)
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseDate(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM-DD
    val formatter = DateTimeFormatterBuilder() // date and offset
        .parseCaseInsensitive()
        .append(ISO_LOCAL_DATE)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseTimeWithTimezoneSecondsFraction(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm:ss.sss+05:00
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(hourMinuteSecondsFractionFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .append(dateTimeDefaults)
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseTimeWithTimezoneSeconds(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm:ss+05:00
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(hourMinuteSecondsFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .append(dateTimeDefaults)
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseTimeWithTimezone(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm+05:00
    val formatter = DateTimeFormatterBuilder()
        .append(hourMinuteFormatter)
        .parseLenient()
        .appendOffsetId()
        .parseStrict()
        .append(dateTimeDefaults)
        .toFormatter()
    ZonedDateTime.parse(input, formatter)
}

private fun parseTimeWithSecondsFractals(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm:ss.sss
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(hourMinuteSecondsFractionFormatter)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseTimeWithSeconds(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm:ss
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(hourMinuteSecondsFormatter)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseTime(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // HH:mm
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(hourMinuteFormatter)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseYearMonth(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY-MM
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .appendValue(YEAR)
        .appendLiteral("-")
        .appendValue(MONTH_OF_YEAR)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private fun parseYear(input: String): Result<ZonedDateTime, Throwable> = runSuspendCatching {
    // YYYY
    val formatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .appendValue(YEAR)
        .append(dateTimeDefaults)
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    ZonedDateTime.parse(input, formatter)
}

private val hourMinuteFormatter = DateTimeFormatterBuilder()
    .appendValue(HOUR_OF_DAY, 2)
    .appendLiteral(":")
    .appendValue(MINUTE_OF_HOUR, 2)
    .toFormatter()

private val hourMinuteSecondsFormatter = DateTimeFormatterBuilder()
    .append(hourMinuteFormatter)
    .appendLiteral(":")
    .appendValue(SECOND_OF_MINUTE, 2)
    .toFormatter()

private val hourMinuteSecondsFractionFormatter = DateTimeFormatterBuilder()
    .append(hourMinuteSecondsFormatter)
    .appendFraction(NANO_OF_SECOND, 1, 9, true)
    .toFormatter()

private val dateTimeDefaults = DateTimeFormatterBuilder()
    .parseDefaulting(YEAR, 0)
    .parseDefaulting(MONTH_OF_YEAR, 1)
    .parseDefaulting(DAY_OF_MONTH, 1)
    .parseDefaulting(HOUR_OF_DAY, 0) // define default values
    .parseDefaulting(MINUTE_OF_HOUR, 0)
    .toFormatter()
