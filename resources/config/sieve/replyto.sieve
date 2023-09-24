
set "rto_raw" "%{to_lowercase(header.reply-to.raw)}";
if eval "!is_empty(rto_raw)" {
    set "rto_addr" "%{to_lowercase(header.reply-to.addr)}";
    set "rto_name" "%{to_lowercase(header.reply-to.name)}";

    if eval "is_email(rto_addr)" {
        set "t.HAS_REPLYTO" "1";

        if eval "eq_ignore_case(header.reply-to, header.from)" {
            set "t.REPLYTO_EQ_FROM" "1";
        } else {
            set "from_addr" "%{to_lowercase(header.from.addr)}";
            set "from_domain" "%{domain_part(email_part(from_addr, 'domain'), 'sld')}";

            if eval "domain_part(email_part(rto_addr, 'domain'), 'sld') == from_domain" {
                set "t.REPLYTO_DOM_EQ_FROM_DOM" "1";
            } else {
                set "is_from_list" "%{!is_empty(header.List-Unsubscribe:List-Id:X-To-Get-Off-This-List:X-List:Auto-Submitted[*])}";
                if eval "!is_from_list && contains_ignore_case(header.to:cc:bcc[*].addr[*], rto_addr)"  {
                    set "t.REPLYTO_EQ_TO_ADDR" "1";
                } else {
                    set "t.REPLYTO_DOM_NEQ_FROM_DOM" "1";
                }

                if eval "!is_from_list &&
                         !eq_ignore_case(from_addr, header.to.addr) && 
                         !(count(envelope.to) == 1 && envelope.to[0] == from_addr)" {
                    set "i" "%{count(envelope.to)}";
                    set "found_domain" "0";

                    while "i != 0" {
                        set "i" "%{i - 1}";

                        if eval "domain_part(email_part(envelope.to[i], 'domain'), 'sld') == from_domain" {
                            set "found_domain" "1";
                            break;
                        }
                    }

                    if eval "!found_domain" {
                        set "t.SPOOF_REPLYTO" "1";
                    }
                }
            }

            if eval "!is_empty(rto_name) && eq_ignore_case(rto_name, header.from.name)" {
                set "t.REPLYTO_DN_EQ_FROM_DN" "1";
            }
        }

    } else {
        set "t.REPLYTO_UNPARSEABLE" "1";
    }

    if eval "is_ascii(header.reply-to) && contains(rto_raw, '=?') && contains(rto_raw, '?=')" {
        if eval "contains(rto_raw, '?q?')" {
            # Reply-To header is unnecessarily encoded in quoted-printable
            set "t.REPLYTO_EXCESS_QP" "1";
        } elsif eval "contains(rto_raw, '?b?')" {
            # Reply-To header is unnecessarily encoded in base64
            set "t.REPLYTO_EXCESS_BASE64" "1";
        }
    }

    if eval "contains(rto_name, 'mr. ') || contains(rto_name, 'ms. ') || contains(rto_name, 'mrs. ') || contains(rto_name, 'dr. ')" {
        set "t.REPLYTO_EMAIL_HAS_TITLE" "1";
    }
}

