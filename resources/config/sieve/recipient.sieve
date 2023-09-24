
set "to_raw" "%{to_lowercase(header.to.raw)}";
if eval "!is_empty(to_raw)" {
    if eval "is_ascii(header.to) && contains(to_raw, '=?') && contains(to_raw, '?=')" {
        if eval "contains(to_raw, '?q?')" {
            # To header is unnecessarily encoded in quoted-printable
            set "t.TO_EXCESS_QP" "1";
        } elsif eval "contains(to_raw, '?b?')" {
            # To header is unnecessarily encoded in base64
            set "t.TO_EXCESS_BASE64" "1";
        }
    } elsif eval "!is_ascii(to_raw) && !env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
        # To needs encoding
        set "t.TO_NEEDS_ENCODING" "1";
    }
} else {
    set "t.MISSING_TO" "1";
}

set "rcpt_addr" "%{to_lowercase(header.to:cc:bcc[*].addr[*])}";
set "rcpt_count" "%{count(winnow(rcpt_addr))}";

if eval "rcpt_count > 0" {
    if eval "rcpt_count == 1" {
        set "t.RCPT_COUNT_ONE" "1";
    } elsif eval "rcpt_count == 2" {
        set "t.RCPT_COUNT_TWO" "1";
    } elsif eval "rcpt_count == 3" {
        set "t.RCPT_COUNT_THREE" "1";
    } elsif eval "rcpt_count <= 5" {
        set "t.RCPT_COUNT_FIVE" "1";
    } elsif eval "rcpt_count <= 7" {
        set "t.RCPT_COUNT_SEVEN" "1";
    } elsif eval "rcpt_count <= 12" {
        set "t.RCPT_COUNT_TWELVE" "1";
    } else {
        set "t.RCPT_COUNT_GT_50" "1";
    }

    set "rcpt_name" "%{to_lowercase(header.to:cc:bcc[*].name[*])}";
    set "i" "%{count(rcpt_addr)}";
    set "to_dn_count" "0";
    set "to_dn_eq_addr_count" "0";
    set "to_match_envrcpt" "0";
    set "subject" "%{to_lowercase(thread_name(header.subject))}";

    while "i != 0" {
        set "i" "%{i - 1}";
        set "addr" "%{rcpt_addr[i]}";

        if eval "!is_empty(addr)" {
            set "name" "%{rcpt_name[i]}";

            if eval "!is_empty(name)" {
                if eval "name == addr" {
                    set "to_dn_eq_addr_count" "%{to_dn_eq_addr_count + 1}";
                } else {
                    set "to_dn_count" "%{to_dn_count + 1}";
                    if eval "name == 'recipient' || name == 'recipients'" {
                        set "t.TO_DN_RECIPIENTS" "1";
                    }
                }
            }

            if eval "contains(envelope.to, addr)" {
                set "to_match_envrcpt" "%{to_match_envrcpt + 1}";
            }

            # Check if the local part is present in the subject
            set "local_part" "%{email_part(addr, 'local')}";
            if eval "contains(subject, addr)" {
                set "t.RCPT_ADDR_IN_SUBJECT" "1";
            } elsif eval "len(local_part) > 3 && contains(subject, local_part)" {
                set "t.RCPT_LOCAL_IN_SUBJECT" "1";
            }

            if eval "contains(local_part, '+')" {
                set "t.TAGGED_RCPT" "1";
            }
        }
    }

    if eval "to_dn_count == 0 && to_dn_eq_addr_count == 0" {
        set "t.TO_DN_NONE" "1";
    } elsif eval "to_dn_count == rcpt_count" {
        set "t.TO_DN_ALL" "1";
    } elsif eval "to_dn_count > 0" {
        set "t.TO_DN_SOME" "1";
    }

    if eval "to_dn_eq_addr_count == rcpt_count" {
        set "t.TO_DN_EQ_ADDR_ALL" "1";
    } elsif eval "to_dn_eq_addr_count > 0" {
        set "t.TO_DN_EQ_ADDR_SOME" "1";
    }

    if eval "to_match_envrcpt == rcpt_count" {
        set "t.TO_MATCH_ENVRCPT_ALL" "1";
    } else {
        if eval "to_match_envrcpt > 0" {
            set "t.TO_MATCH_ENVRCPT_SOME" "1";
        }

        if eval "is_empty(header.List-Unsubscribe:List-Id[*])" {
            set "i" "%{count(envelope.to)}";
            while "i != 0" {
                set "i" "%{i - 1}";
                set "env_rcpt" "%{envelope.to[i]}";

                if eval "!contains(rcpt_addr, env_rcpt) && env_rcpt != envelope.from" {
                    set "t.FORGED_RECIPIENTS" "1";
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
        set "t.HFILTER_RCPT_BOUNCEMOREONE" "1";
    }
} else {
    set "t.RCPT_COUNT_ZERO" "1";

    if eval "contains(to_raw, 'undisclosed') && contains(to_raw, 'recipients')" {
        set "t.R_UNDISC_RCPT" "1";
    }
}
