
if eval "(contains(subject_lc, 'delivery') && 
            (contains(subject_lc, 'failed') || 
             contains(subject_lc, 'report') || 
             contains(subject_lc, 'status') || 
             contains(subject_lc, 'warning'))) ||
         (contains(subject_lc, 'failure') && 
            (contains(subject_lc, 'delivery') || 
             contains(subject_lc, 'notice') || 
             contains(subject_lc, 'mail') )) ||
         (contains(subject_lc, 'delivered') &&
            (contains(subject_lc, 'couldn\\'t be') || 
             contains(subject_lc, 'could not be') || 
             contains(subject_lc, 'hasn\\'t been') || 
             contains(subject_lc, 'has not been'))) ||
         contains(subject_lc, 'returned mail') ||
         contains(subject_lc, 'undeliverable') || 
         contains(subject_lc, 'undelivered')" {
    # Subject contains words or phrases typical for DSN
    let "t.SUBJ_BOUNCE_WORDS" "1";
}

if eval "is_empty(envelope.from)" {
    if eval "eq_ignore_case(header.content-type, 'multipart/report') && 
             ( eq_ignore_case(header.content-type.attr.report-type, 'delivery-status') ||
               eq_ignore_case(header.content-type.attr.report-type, 'disposition-notification'))" {
        let "t.BOUNCE" "1";
    } else {
        let "from" "to_lowercase(header.from)";

        if eval "contains(from, 'mdaemon') && !is_empty(header.X-MDDSN-Message)" {
            let "t.BOUNCE" "1";
        } elsif eval "contains(from, 'postmaster') || contains(from, 'mailer-daemon')" {
            if eval "t.SUBJ_BOUNCE_WORDS" {
                let "t.BOUNCE" "1";
            } else {
                foreverypart {
                    if eval "(eq_ignore_case(header.content-type.type, 'message') ||
                              eq_ignore_case(header.content-type.type, 'text')) &&
                             (eq_ignore_case(header.content-type.subtype, 'rfc822-headers') ||
                              eq_ignore_case(header.content-type.subtype, 'rfc822'))" {
                        let "t.BOUNCE" "1";
                        break;
                    }
                }
            }
        }
    }
}
