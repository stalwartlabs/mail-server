
let "to_raw" "to_lowercase(header.to.raw)";
if eval "!is_empty(to_raw)" {
    if eval "is_ascii(header.to) && contains(to_raw, '=?') && contains(to_raw, '?=')" {
        if eval "contains(to_raw, '?q?')" {
            # To header is unnecessarily encoded in quoted-printable
            let "t.TO_EXCESS_QP" "1";
        } elsif eval "contains(to_raw, '?b?')" {
            # To header is unnecessarily encoded in base64
            let "t.TO_EXCESS_BASE64" "1";
        }
    } elsif eval "!is_ascii(to_raw) && !env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
        # To needs encoding
        let "t.TO_NEEDS_ENCODING" "1";
    }
} else {
    let "t.MISSING_TO" "1";
}

let "rcpt_count" "count(recipients_clean)";

if eval "rcpt_count > 0" {
    if eval "rcpt_count == 1" {
        let "t.RCPT_COUNT_ONE" "1";
    } elsif eval "rcpt_count == 2" {
        let "t.RCPT_COUNT_TWO" "1";
    } elsif eval "rcpt_count == 3" {
        let "t.RCPT_COUNT_THREE" "1";
    } elsif eval "rcpt_count <= 5" {
        let "t.RCPT_COUNT_FIVE" "1";
    } elsif eval "rcpt_count <= 7" {
        let "t.RCPT_COUNT_SEVEN" "1";
    } elsif eval "rcpt_count <= 12" {
        let "t.RCPT_COUNT_TWELVE" "1";
    } else {
        let "t.RCPT_COUNT_GT_50" "1";
    }

    let "rcpt_name" "to_lowercase(header.to:cc:bcc[*].name[*])";
    let "i" "count(recipients)";
    let "to_dn_count" "0";
    let "to_dn_eq_addr_count" "0";
    let "to_match_envrcpt" "0";

    while "i != 0" {
        let "i" "i - 1";
        let "addr" "recipients[i]";

        if eval "!is_empty(addr)" {
            let "name" "rcpt_name[i]";

            if eval "!is_empty(name)" {
                if eval "name == addr" {
                    let "to_dn_eq_addr_count" "to_dn_eq_addr_count + 1";
                } else {
                    let "to_dn_count" "to_dn_count + 1";
                    if eval "name == 'recipient' || name == 'recipients'" {
                        let "t.TO_DN_RECIPIENTS" "1";
                    }
                }
            }

            if eval "contains(envelope.to, addr)" {
                let "to_match_envrcpt" "to_match_envrcpt + 1";
            }

            # Check if the local part is present in the subject
            let "local_part" "email_part(addr, 'local')";
            if eval "!is_empty(local_part)" {
                if eval "contains(subject_lc, addr)" {
                    let "t.RCPT_ADDR_IN_SUBJECT" "1";
                } elsif eval "len(local_part) > 3 && contains(subject_lc, local_part)" {
                    let "t.RCPT_LOCAL_IN_SUBJECT" "1";
                }

                if eval "contains(local_part, '+')" {
                    let "t.TAGGED_RCPT" "1";
                }
            }

            # Check if it is an into to info 
            if eval "!t.INFO_TO_INFO_LU && 
                     local_part == 'info' && 
                     from_local == 'info' && 
                     header.List-Unsubscribe.exists" {
                let "t.INFO_TO_INFO_LU" "1";
            }

            # Check for freemail or disposable domains
            let "domain" "domain_part(email_part(addr, 'domain'), 'sld')";
            if eval "!is_empty(domain)" {
                if eval "lookup('spam/free-domains', domain)" {
                    if eval "!t.FREEMAIL_TO && contains_ignore_case(recipients_to, addr)" {
                        let "t.FREEMAIL_TO" "1";
                    } elsif eval "!t.FREEMAIL_CC && contains_ignore_case(recipients_cc, addr)" {
                        let "t.FREEMAIL_CC" "1";
                    }
                } elsif eval "lookup('spam/disposable-domains', domain)" {
                    if eval "!t.DISPOSABLE_TO && contains_ignore_case(recipients_to, addr)" {
                        let "t.DISPOSABLE_TO" "1";
                    } elsif eval "!t.DISPOSABLE_CC && contains_ignore_case(recipients_cc, addr)" {
                        let "t.DISPOSABLE_CC" "1";
                    }
                }
            }
        }
    }

    if eval "to_dn_count == 0 && to_dn_eq_addr_count == 0" {
        let "t.TO_DN_NONE" "1";
    } elsif eval "to_dn_count == rcpt_count" {
        let "t.TO_DN_ALL" "1";
    } elsif eval "to_dn_count > 0" {
        let "t.TO_DN_SOME" "1";
    }

    if eval "to_dn_eq_addr_count == rcpt_count" {
        let "t.TO_DN_EQ_ADDR_ALL" "1";
    } elsif eval "to_dn_eq_addr_count > 0" {
        let "t.TO_DN_EQ_ADDR_SOME" "1";
    }

    if eval "to_match_envrcpt == rcpt_count" {
        let "t.TO_MATCH_ENVRCPT_ALL" "1";
    } else {
        if eval "to_match_envrcpt > 0" {
            let "t.TO_MATCH_ENVRCPT_SOME" "1";
        }

        if eval "is_empty(header.List-Unsubscribe:List-Id[*])" {
            let "i" "count(envelope.to)";
            while "i != 0" {
                let "i" "i - 1";
                let "env_rcpt" "envelope.to[i]";

                if eval "!contains(recipients, env_rcpt) && env_rcpt != envelope.from" {
                    let "t.FORGED_RECIPIENTS" "1";
                    break;
                }
            }
        }
    }

    # Message from bounce and over 1 recipient
    if eval "rcpt_count > 1 &&
             (is_empty(envelope.from) || 
              envfrom_local == 'postmaster' || 
              envfrom_local == 'mailer-daemon')" {
        let "t.RCPT_BOUNCEMOREONE" "1";
    }

    # Check for sorted recipients
    if eval "rcpt_count >= 7 && sort(recipients_clean, false) == recipients_clean" {
        let "t.SORTED_RECIPS" "1";
    }

    # Check for suspiciously similar recipients
    if eval "!t.SORTED_RECIPS && rcpt_count => 5" {
        let "i" "rcpt_count";
        let "hits" "0";
        let "combinations" "0";

        while "i" {
            let "i" "i - 1";
            let "j" "i";
            while "j" {
                let "j" "j - 1";
                let "a" "recipients_clean[i]";
                let "b" "recipients_clean[j]";

                if eval "levenshtein_distance(email_part(a, 'local'), email_part(b, 'local')) < 3" {
                    let "hits" "hits + 1";
                }

                let "a" "email_part(a, 'domain')";
                let "b" "email_part(b, 'domain')";

                if eval "a != b && levenshtein_distance(a, b) < 4" {
                    let "hits" "hits + 1";
                }

                let "combinations" "combinations + 1";
            }
        }

        if eval "hits / combinations > 0.65" {
            let "t.SUSPICIOUS_RECIPS" "1";
        }
    }

    # Check for spaces in recipient addresses
    let "raw_to" "header.to:cc[*].raw";
    let "i" "len(raw_to)";
    while "i != 0" {
        let "i" "i - 1";
        let "raw_addr" "rsplit(raw_to[i], '<')[0]";
        if eval "contains(raw_addr, '>') && (starts_with(raw_addr, ' ' ) || ends_with(raw_addr, ' >'))" {
            let "t.TO_WRAPPED_IN_SPACES" "1";
            break;
        }
    }

} else {
    let "t.RCPT_COUNT_ZERO" "1";

    if eval "contains(to_raw, 'undisclosed') && contains(to_raw, 'recipients')" {
        let "t.R_UNDISC_RCPT" "1";
    }
}
