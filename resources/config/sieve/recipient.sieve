
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

let "rcpt_addr" "to_lowercase(header.to:cc:bcc[*].addr[*])";
let "rcpt_count" "count(winnow(rcpt_addr))";

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
    let "i" "count(rcpt_addr)";
    let "to_dn_count" "0";
    let "to_dn_eq_addr_count" "0";
    let "to_match_envrcpt" "0";
    let "subject" "to_lowercase(thread_name(header.subject))";

    while "i != 0" {
        let "i" "i - 1";
        let "addr" "rcpt_addr[i]";

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
                if eval "contains(subject, addr)" {
                    let "t.RCPT_ADDR_IN_SUBJECT" "1";
                } elsif eval "len(local_part) > 3 && contains(subject, local_part)" {
                    let "t.RCPT_LOCAL_IN_SUBJECT" "1";
                }

                if eval "contains(local_part, '+')" {
                    let "t.TAGGED_RCPT" "1";
                }
            }

            # Check for freemail or disposable domains
            let "domain" "domain_part(email_part(addr, 'domain'), 'sld')";
            if eval "!is_empty(domain)" {
                if string :list "${domain}" "spam/free-domains" {
                    if eval "!t.FREEMAIL_TO && contains_ignore_case(header.to[*].addr[*], addr)" {
                        let "t.FREEMAIL_TO" "1";
                    } elsif eval "!t.FREEMAIL_CC && contains_ignore_case(header.cc[*].addr[*], addr)" {
                        let "t.FREEMAIL_CC" "1";
                    }
                } elsif string :list "${domain}" "spam/disposable-domains" {
                    if eval "!t.DISPOSABLE_TO && contains_ignore_case(header.to[*].addr[*], addr)" {
                        let "t.DISPOSABLE_TO" "1";
                    } elsif eval "!t.DISPOSABLE_CC && contains_ignore_case(header.cc[*].addr[*], addr)" {
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

                if eval "!contains(rcpt_addr, env_rcpt) && env_rcpt != envelope.from" {
                    let "t.FORGED_RECIPIENTS" "1";
                    break;
                }
            }
        }
    }

    # Message from bounce and over 1 recipient
    if eval "rcpt_count > 1 &&
             (is_empty(envelope.from) || 
              starts_with(envelope.from, 'postmaster@') || 
              starts_with(envelope.from, 'mailer-daemon@'))" {
        let "t.HFILTER_RCPT_BOUNCEMOREONE" "1";
    }
} else {
    let "t.RCPT_COUNT_ZERO" "1";

    if eval "contains(to_raw, 'undisclosed') && contains(to_raw, 'recipients')" {
        let "t.R_UNDISC_RCPT" "1";
    }
}
