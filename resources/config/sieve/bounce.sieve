
set "subject" "%{to_lowercase(header.subject)}";

if eval "(contains(subject, 'delivery') && 
            (contains(subject, 'failed') || 
             contains(subject, 'report') || 
             contains(subject, 'status') || 
             contains(subject, 'warning'))) ||
         (contains(subject, 'failure') && 
            (contains(subject, 'delivery') || 
             contains(subject, 'notice') || 
             contains(subject, 'mail') )) ||
         (contains(subject, 'delivered') &&
            (contains(subject, 'couldn\\'t be') || 
             contains(subject, 'could not be') || 
             contains(subject, 'hasn\\'t been') || 
             contains(subject, 'has not been'))) ||
         contains(subject, 'returned mail') ||
         contains(subject, 'undeliverable') || 
         contains(subject, 'undelivered')" {
    # Subject contains words or phrases typical for DSN
    set "t.SUBJ_BOUNCE_WORDS" "1";
}

if eval "is_empty(envelope.from)" {
    if eval "eq_ignore_case(header.content-type, 'multipart/report') && 
             ( eq_ignore_case(header.content-type.attr.report-type, 'delivery-status') ||
               eq_ignore_case(header.content-type.attr.report-type, 'disposition-notification'))" {
        set "t.BOUNCE" "1";
    } else {
        set "from" "%{to_lowercase(header.from)}";

        if eval "contains(from, 'mdaemon') && !is_empty(header.X-MDDSN-Message)" {
            set "t.BOUNCE" "1";
        } elsif eval "contains(from, 'postmaster') || contains(from, 'mailer-daemon')" {
            if eval "t.SUBJ_BOUNCE_WORDS" {
                set "t.BOUNCE" "1";
            } else {
                foreverypart {
                    if eval "(eq_ignore_case(header.content-type.type, 'message') ||
                              eq_ignore_case(header.content-type.type, 'text')) &&
                             (eq_ignore_case(header.content-type.subtype, 'rfc822-headers') ||
                              eq_ignore_case(header.content-type.subtype, 'rfc822'))" {
                        set "t.BOUNCE" "1";
                        break;
                    }
                }
            }
        }
    }
}
