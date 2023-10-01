if eval "header.date.exists" {
    let "date" "header.date.date";

    if eval "date != 0" {
        let "date_diff" "env.now - date";

        if eval "date_diff > 86400" {
            # Older than a day
            let "t.DATE_IN_PAST" "1";
        } elsif eval "-date_diff > 7200" {
            # More than 2 hours in the future
            let "t.DATE_IN_FUTURE" "1";
        }
    } else {
        let "t.INVALID_DATE" "1";
    }
} else {
    let "t.MISSING_DATE" "1";
}
