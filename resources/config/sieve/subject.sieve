
let "raw_subject_lc" "to_lowercase(header.subject.raw)";
let "is_ascii_subject" "is_ascii(subject_lc)";

if eval "len(subject_clean) >= 10 && count(tokenize(subject_clean, 'words')) > 1 && is_uppercase(subject_clean)" {
    # Subject contains mostly capital letters
	let "t.SUBJ_ALL_CAPS" "1";
}

if eval "count_chars(subject_clean) > 200" {
    # Subject is very long
    let "t.LONG_SUBJ" "1";
}

if eval "!is_empty(tokenize(subject_lc, 'uri_strict'))" {
    # Subject contains a URL
    let "t.URL_IN_SUBJECT" "1";
}

if eval "!is_ascii(raw_subject_lc) && !env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
    # Subject needs encoding
    let "t.SUBJECT_NEEDS_ENCODING" "1";
}

if eval "!header.Subject.exists" {
    # Missing subject header
    let "t.MISSING_SUBJECT" "1";
} elsif eval "is_empty(trim(subject_lc))" {
    # Subject is empty
    let "t.EMPTY_SUBJECT" "1";
}

if eval "is_ascii(subject_lc) && contains(raw_subject_lc, '=?') && contains(raw_subject_lc, '?=')" {
    if eval "contains(raw_subject_lc, '?q?')" {
        # Subject header is unnecessarily encoded in quoted-printable
        let "t.SUBJ_EXCESS_QP" "1";
    } elsif eval "contains(raw_subject_lc, '?b?')" {
        # Subject header is unnecessarily encoded in base64
        let "t.SUBJ_EXCESS_BASE64" "1";
    }
}

if eval "starts_with(subject_lc, 're:') && is_empty(header.in-reply-to) && is_empty(header.references)" {
    # Fake reply
    let "t.FAKE_REPLY" "1";
}

let "subject_lc_trim" "trim_end(subject_lc)";
if eval "subject_lc != subject_lc_trim" {
    # Subject ends with space characters
    let "t.SUBJECT_ENDS_SPACES" "1";
}

if eval "contains(subject_lc, '$') || 
         contains(subject_lc, '€') || 
         contains(subject_lc, '£') || 
         contains(subject_lc, '¥')" {
    # Subject contains currency symbols
    let "t.SUBJECT_HAS_CURRENCY" "1";
}

if eval "ends_with(subject_lc_trim, '!')" {
    # Subject ends with an exclamation mark
    let "t.SUBJECT_ENDS_EXCLAIM" "1";
} elsif eval "ends_with(subject_lc_trim, '?')" {
    # Subject ends with a question mark
    let "t.SUBJECT_ENDS_QUESTION" "1";
}

if eval "contains(subject_lc_trim, '!')" {
    # Subject contains an exclamation mark
    let "t.SUBJECT_HAS_EXCLAIM" "1";
}

if eval "contains(subject_lc_trim, '?')" {
    # Subject contains a question mark
    let "t.SUBJECT_HAS_QUESTION" "1";
}
