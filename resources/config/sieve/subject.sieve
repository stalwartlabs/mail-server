
set "thread_name" "%{thread_name(header.subject)}";
set "subject_lcase" "%{to_lowercase(header.subject)}";
set "raw_subject_lcase" "%{to_lowercase(header.subject.raw)}";
set "is_ascii_subject" "%{is_ascii(subject_lcase)}";

if eval "len(thread_name) >= 10 && count(tokenize_words(thread_name)) > 1 && is_uppercase(thread_name)" {
    # Subject contains mostly capital letters
	set "t.SUBJ_ALL_CAPS" "1";
}

if eval "count_chars(thread_name) > 200" {
    # Subject is very long
    set "t.SUBJ_VERY_LONG" "1";
}

if eval "contains(subject_lcase, 'http://') || contains(subject_lcase, 'https://')" {
    # Subject contains a URL
    set "t.URL_IN_SUBJECT" "1";
}

if eval "!is_ascii(raw_subject_lcase) && !env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
    # Subject needs encoding
    set "t.SUBJECT_NEEDS_ENCODING" "1";
}

if not exists "Subject" {
    # Missing subject header
    set "t.MISSING_SUBJECT" "1";
} elsif eval "is_empty(trim(subject_lcase))" {
    # Subject is empty
    set "t.EMPTY_SUBJECT" "1";
}

if eval "is_ascii(subject_lcase) && contains(raw_subject_lcase, '=?') && contains(raw_subject_lcase, '?=')" {
    if eval "contains(raw_subject_lcase, '?q?')" {
        # Subject header is unnecessarily encoded in quoted-printable
        set "t.SUBJ_EXCESS_QP" "1";
    } elsif eval "contains(raw_subject_lcase, '?b?')" {
        # Subject header is unnecessarily encoded in base64
        set "t.SUBJ_EXCESS_BASE64" "1";
    }
}

if eval "starts_with(subject_lcase, 're:') && is_empty(header.in-reply-to) && is_empty(header.references)" {
    # Fake reply
    set "t.FAKE_REPLY" "1";
}

set "subject_lcase_trim" "%{trim_end(subject_lcase)}";
if eval "subject_lcase != subject_lcase_trim" {
    # Subject ends with space characters
    set "t.SUBJECT_ENDS_SPACES" "1";
}

if eval "contains(subject_lcase, '$') || 
         contains(subject_lcase, '€') || 
         contains(subject_lcase, '£') || 
         contains(subject_lcase, '¥')" {
    # Subject contains currency symbols
    set "t.SUBJECT_HAS_CURRENCY" "1";
}

if eval "ends_with(subject_lcase_trim, '!')" {
    # Subject ends with an exclamation mark
    set "t.SUBJECT_ENDS_EXCLAIM" "1";
} elsif eval "ends_with(subject_lcase_trim, '?')" {
    # Subject ends with a question mark
    set "t.SUBJECT_ENDS_QUESTION" "1";
}

if eval "contains(subject_lcase_trim, '!')" {
    # Subject contains an exclamation mark
    set "t.SUBJECT_HAS_EXCLAIM" "1";
}

if eval "contains(subject_lcase_trim, '?')" {
    # Subject contains a question mark
    set "t.SUBJECT_HAS_QUESTION" "1";
}
