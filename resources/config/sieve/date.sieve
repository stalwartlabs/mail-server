if eval "!is_empty(header.date.raw)" {
    set "date" "%{header.date.date}";

    if eval "date != 0" {
        set "date_diff" "%{env.now - date}";

        if eval "date_diff > 86400" {
            # Older than a day
            set "t.DATE_IN_PAST" "1";
        } elsif eval "-date_diff > 7200" {
            # More than 2 hours in the future
            set "t.DATE_IN_FUTURE" "1";
        }
    } else {
        set "t.INVALID_DATE" "1";
    }
} else {
    set "t.MISSING_DATE" "1";
}
