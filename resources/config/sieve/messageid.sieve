let "mid_raw" "trim(header.message-id.raw)";

if eval "!is_empty(mid_raw)" {
    let "mid_lcase" "to_lowercase(header.message-id)";
    let "mid_rhs" "email_part(mid_lcase, 'domain')";

    if eval "!is_empty(mid_rhs)" {
        if eval "starts_with(mid_rhs, '[') && ends_with(mid_rhs, ']') && is_ip_addr(strip_suffix(strip_prefix(mid_rhs, '['), ']'))" {
            let "t.MID_RHS_IP_LITERAL" "1";
        } elsif eval "is_ip_addr(mid_rhs)" {
            let "t.MID_BARE_IP" "1";
        } elsif eval "!contains(mid_rhs, '.')" {
            let "t.MID_RHS_NOT_FQDN" "1";
        }

        if eval "starts_with(mid_rhs, 'www.')" {
            let "t.MID_RHS_WWW" "1";
        }

        if eval "!is_ascii(mid_raw) || contains(mid_raw, '(') || starts_with(mid_lcase, '@')" {
            let "t.INVALID_MSGID" "1";
        }

        # From address present in Message-ID checks
        let "sender" "from_addr";
        if eval "is_empty(sender)" {
            let "sender" "envelope.from";
        }
        if eval "!is_empty(sender)" {
            if eval "contains(mid_lcase, sender)" {
                let "t.MID_CONTAINS_FROM" "1";
            } else {
                let "from_domain" "email_part(sender, 'domain')";
                let "mid_sld" "domain_part(mid_rhs, 'sld')";

                if eval "mid_rhs == from_domain" {
                    let "t.MID_RHS_MATCH_FROM" "1";
                } elsif eval "!is_empty(mid_sld) && domain_part(from_domain, 'sld') == mid_sld" {
                    let "t.MID_RHS_MATCH_FROMTLD" "1";
                }
            }
        }

        # To/Cc addresses present in Message-ID checks
        let "recipients_len" "count(recipients)";        
        let "i" "0";

        while "i < recipients_len" {
            let "rcpt" "recipients[i]";
            let "i" "i + 1";
            if eval "contains(mid_lcase, rcpt)" {
                let "t.MID_CONTAINS_TO" "1";
            } elsif eval "email_part(rcpt, 'domain') == mid_rhs" {
                let "t.MID_RHS_MATCH_TO" "1";
            }
        }
    } else {
        let "t.INVALID_MSGID" "1";
    }

    if eval "!starts_with(mid_raw, '<') || !contains(mid_raw, '>')" {
        let "t.MID_MISSING_BRACKETS" "1";
    }

} else {
    let "t.MISSING_MID" "1";
}

