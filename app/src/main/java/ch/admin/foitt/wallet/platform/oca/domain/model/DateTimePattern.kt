package ch.admin.foitt.wallet.platform.oca.domain.model

enum class DateTimePattern(val pattern: String) {
    DATE_TIME_TIMEZONE_SECONDS_FRACTION("yyyy-MM-dd, HH:mm:ss.SSS"),
    DATE_TIME_TIMEZONE_SECONDS("yyyy-MM-dd, HH:mm:ss"),
    DATE_TIME_TIMEZONE("yyyy-MM-dd, HH:mm"),

    DATE_TIME_SECONDS_FRACTION("yyyy-MM-dd, HH:mm:ss.SSS"),
    DATE_TIME_SECONDS("yyyy-MM-dd, HH:mm:ss"),
    DATE_TIME("yyyy-MM-dd, HH:mm"),

    DATE_TIMEZONE("yyyy-MM-dd"),
    DATE("yyyy-MM-dd"),

    TIME_TIMEZONE_SECONDS_FRACTION("HH:mm:ss.SSS"),
    TIME_TIMEZONE_SECONDS("HH:mm:ss"),
    TIME_TIMEZONE("HH:mm"),

    TIME_SECONDS_FRACTION("HH:mm:ss.SSS"),
    TIME_SECONDS("HH:mm:ss"),
    TIME("HH:mm"),

    YEAR_MONTH("yyyy-MMMM"),
    YEAR("yyyy");

    companion object {
        fun getPatternFor(name: String?): DateTimePattern? {
            return DateTimePattern.entries.firstOrNull { it.name == name }
        }
    }
}
