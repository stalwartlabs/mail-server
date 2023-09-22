set "mid_raw" "%{trim(header.message-id.raw)}";

if eval "!is_empty(mid_raw)" {
    set "mid_lcase" "%{to_lowercase(header.message-id)}";
    set "mid_rhs" "%{email_part(mid_lcase, 'domain')}";

    if eval "!is_empty(mid_rhs)" {
        if eval "starts_with(mid_rhs, '[') && ends_with(mid_rhs, ']') && is_ip_addr(strip_suffix(strip_prefix(mid_rhs, '['), ']'))" {
            set "t.MID_RHS_IP_LITERAL" "1";
        } elsif eval "is_ip_addr(mid_rhs)" {
            set "t.MID_BARE_IP" "1";
        } elsif eval "!contains(mid_rhs, '.')" {
            set "t.MID_RHS_NOT_FQDN" "1";
        }

        if eval "starts_with(mid_rhs, 'www.')" {
            set "t.MID_RHS_WWW" "1";
        }

        if eval "!is_ascii(mid_raw) || contains(mid_raw, '(') || starts_with(mid_lcase, '@')" {
            set "t.INVALID_MSGID" "1";
        }

        # From address present in Message-ID checks
        set "from_lcase" "%{to_lowercase(header.from.addr)}";
        if eval "is_empty(from_lcase)" {
            set "from_lcase" "%{envelope.from}";
        }
        if eval "!is_empty(from_lcase)" {
            if eval "contains(mid_lcase, from_lcase)" {
                set "t.MID_CONTAINS_FROM" "1";
            } else {
                set "from_domain" "%{email_part(from_lcase, 'domain')}";
                set "mid_sld" "%{domain_part(mid_rhs, 'sld')}";

                if eval "mid_rhs == from_domain" {
                    set "t.MID_RHS_MATCH_FROM" "1";
                } elsif eval "!is_empty(mid_sld) && domain_part(from_domain, 'sld') == mid_sld" {
                    set "t.MID_RHS_MATCH_FROMTLD" "1";
                }
            }
        }

        # To/Cc addresses present in Message-ID checks
        set "recipients" "%{winnow(header.to:cc[*].addr[*])}";
        set "recipients_len" "%{count(recipients)}";        
        set "i" "0";

        while "i < recipients_len" {
            set "rcpt" "%{to_lowercase(recipients[i])}";
            set "i" "%{i + 1}";
            if eval "contains(mid_lcase, rcpt)" {
                set "t.MID_CONTAINS_TO" "1";
            } elsif eval "email_part(rcpt, 'domain') == mid_rhs" {
                set "t.MID_RHS_MATCH_TO" "1";
            }
        }
    } else {
        set "t.INVALID_MSGID" "1";
    }

    if eval "!starts_with(mid_raw, '<') || !contains(mid_raw, '>')" {
        set "t.MID_MISSING_BRACKETS" "1";
    }

} else {
    set "t.MISSING_MID" "1";
}

