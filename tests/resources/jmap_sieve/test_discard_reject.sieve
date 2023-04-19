require ["duplicate", "ihave", "reject", "body"];

if body :contains "TPS" {
    if duplicate :handle "one_sec_expire" :seconds 1 {
        error "one_sec_expire handle should not be duplicate.";
    }

    if duplicate :uniqueid "one_sec_expire" :seconds 1 {
        error "one_sec_expire uniqueid should not be duplicate.";
    }

    if duplicate :handle "five_secs_expire" :seconds 5 {
        error "five_secs_expire handle should not be duplicate.";
    }

    if duplicate :uniqueid "five_secs_expire" :seconds 5 {
        error "five_secs_expire uniqueid should not be duplicate.";
    }

    discard;
} elsif body :contains "T.P.S." {
    if duplicate :handle "one_sec_expire" :seconds 1 {
        error "one_sec_expire handle should have expired.";
    }

    if duplicate :uniqueid "one_sec_expire" :seconds 1 {
        error "one_sec_expire uniqueid should have expired.";
    }

    if not duplicate :handle "five_secs_expire" :seconds 5 {
        error "five_secs_expire handle should be duplicate.";
    }

    if not duplicate :uniqueid "five_secs_expire" :seconds 5 {
        error "five_secs_expire uniqueid should be duplicate.";
    }

    reject "No soup for you, next!";
} else {
    error "Unexpected body contents.";
}
