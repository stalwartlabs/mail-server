set "from_count" "%{count(header.from[*].raw)}";
set "service_accounts" "%{['www-data', 'anonymous', 'ftp', 'apache', 'nobody', 'guest', 'nginx', 'web', 'www']}";

if eval "from_count > 0" {
    set "from_name" "%{to_lowercase(trim(header.from.name))}";
    set "from_addr" "%{to_lowercase(trim(header.from.addr))}";
    set "from_local" "%{email_part(from_addr, 'local')}";
    set "from_domain" "%{email_part(from_addr, 'domain')}";
    set "from_raw" "%{to_lowercase(header.from.raw)}";

    if eval "from_count > 1" {
        set "t.MULTIPLE_FROM" "1";
    }

    if eval "!is_email(from_addr)" {
        set "t.FROM_INVALID" "1";
    } else {
        if eval "contains(service_accounts, from_local)" {
            set "t.FROM_SERVICE_ACCT" "1";
        }
        if eval "starts_with(from_domain, 'www.')" {
            set "t.WWW_DOT_DOMAIN" "1";
        }
    }

    if eval "is_empty(from_name)" {
        set "t.FROM_NO_DN" "1";
    } elsif eval "eq_ignore_case(from_addr, from_name)" {
        set "t.FROM_DN_EQ_ADDR" "1";
    } else {
        if eval "!t.FROM_INVALID" {
            set "t.FROM_HAS_DN" "1";
        }

        if eval "is_email(from_name)" {
            set "from_name_sld" "%{domain_part(email_part(from_name, 'domain'), 'sld')}";
            if eval "(!t.FROM_INVALID && domain_part(from_domain, 'sld') != from_name_sld) ||
                     (!is_empty(envelope.from) && domain_part(email_part(envelope.from, 'domain'), 'sld') != from_name_sld) ||
                     (is_empty(envelope.from) && domain_part(env.helo_domain, 'sld') != from_name_sld)" {
                set "t.SPOOF_DISPLAY_NAME" "1";
            } else {
                set "t.FROM_NEQ_DISPLAY_NAME" "1";
            }
        } else {
            if eval "contains(from_name, 'mr. ') || contains(from_name, 'ms. ') || contains(from_name, 'mrs. ') || contains(from_name, 'dr. ')" {
                set "t.FROM_NAME_HAS_TITLE" "1";
            }
            if eval "contains(header.from.name, '  ')" {
                set "t.FROM_NAME_EXCESS_SPACE" "1";
            }
        }
    }

    if eval "(!is_empty(envelope.from) && 
               eq_ignore_case(from_addr, envelope.from)) ||
             (is_empty(envelope.from) && 
              !is_empty(from_domain) && 
              domain_part(from_domain, 'sld') == domain_part(env.helo_domain, 'sld') && 
              ( from_local == 'postmaster' || 
                from_local == 'mailer-daemon' || 
                from_local == 'root'))" {
        set "t.FROM_EQ_ENVFROM" "1";
    } elsif eval "!t.FROM_INVALID" {
        set "t.FORGED_SENDER" "1";
        set "t.FROM_NEQ_ENVFROM" "1";
    }

    if eval "contains(from_local, '+')" {
        set "t.TAGGED_FROM" "1";
    }

    set "to" "%{header.to[*].addr[*]}";
    if eval "count(to) == 1" {
        if eval "eq_ignore_case(to, from_addr)" {
            set "t.TO_EQ_FROM" "1";
        } elsif eval "eq_ignore_case(email_part(to, 'domain'), from_domain)" {
            set "t.TO_DOM_EQ_FROM_DOM" "1";
        }
    }

    if eval "!is_ascii(from_raw)" {
        if eval "!env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
            set "t.FROM_NEEDS_ENCODING" "1";
        }
        if eval "!is_header_utf8_valid('From')" {
            set "t.INVALID_FROM_8BIT" "1";
        }
    }

    if eval "is_ascii(header.from) && contains(from_raw, '=?') && contains(from_raw, '?=')" {
        if eval "contains(from_raw, '?q?')" {
            # From header is unnecessarily encoded in quoted-printable
            set "t.FROM_EXCESS_QP" "1";
        } elsif eval "contains(from_raw, '?b?')" {
            # From header is unnecessarily encoded in base64
            set "t.FROM_EXCESS_BASE64" "1";
        }
    }

    if eval "!is_empty(from_name) && !is_empty(from_addr) && !contains(from_raw, ' <')" {
        set "t.R_NO_SPACE_IN_FROM" "1";
    }

    # Read confirmation address is different to from address
    set "crt" "%{header.X-Confirm-Reading-To.addr}";
    if eval "!is_empty(crt) && !eq_ignore_case(from_addr, crt)" {
        set "t.HEADER_RCONFIRM_MISMATCH" "1";
    }
} else {
    set "t.MISSING_FROM" "1";
}

if eval "!is_empty(envelope.from)" {
    if eval "is_email(envelope.from)" {
        if eval "contains(service_accounts, email_part(envelope.from, 'local'))" {
            set "t.ENVFROM_SERVICE_ACCT" "1";
        }
    } else {
        set "t.ENVFROM_INVALID" "1";
    }

    # Read confirmation address is different to return path
    set "dnt" "%{header.Disposition-Notification-To.addr}";
    if eval "!is_empty(dnt) && !eq_ignore_case(envelope.from, dnt)" {
        set "t.HEADER_FORGED_MDN" "1";
    }
}

if eval "!t.FROM_SERVICE_ACCT && 
         (contains_ignore_case(service_accounts, email_part(header.reply-to.addr, 'local')) || 
          contains_ignore_case(service_accounts, email_part(header.sender.addr, 'local')))" {
    set "t.FROM_SERVICE_ACCT" "1";
}

if eval "!t.WWW_DOT_DOMAIN && 
         (contains_ignore_case(header.reply-to.addr, '@www.') || 
          contains_ignore_case(header.sender.addr, '@www.'))" {
    set "t.WWW_DOT_DOMAIN" "1";
}

