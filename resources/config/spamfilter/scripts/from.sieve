let "from_count" "count(header.from[*].raw)";
let "service_accounts" "['www-data', 'anonymous', 'ftp', 'apache', 'nobody', 'guest', 'nginx', 'web', 'www']";

if eval "from_count > 0" {
    let "from_raw" "to_lowercase(header.from.raw)";

    if eval "from_count > 1" {
        let "t.MULTIPLE_FROM" "1";
    }

    if eval "is_email(from_addr)" {
        if eval "contains(service_accounts, from_local)" {
            let "t.FROM_SERVICE_ACCT" "1";
        }
        if eval "starts_with(from_domain, 'www.')" {
            let "t.WWW_DOT_DOMAIN" "1";
        }

        if eval "lookup('spam/free-domains', from_domain_sld)" {
            let "t.FREEMAIL_FROM" "1";
        } elsif eval "lookup('spam/disposable-domains', from_domain_sld)" {
            let "t.DISPOSABLE_FROM" "1";
        }
    } else {
        let "t.FROM_INVALID" "1";
    }

    if eval "is_empty(from_name)" {
        let "t.FROM_NO_DN" "1";
    } elsif eval "eq_ignore_case(from_addr, from_name)" {
        let "t.FROM_DN_EQ_ADDR" "1";
    } else {
        if eval "!t.FROM_INVALID" {
            let "t.FROM_HAS_DN" "1";
        }

        if eval "is_email(from_name)" {
            let "from_name_sld" "domain_part(email_part(from_name, 'domain'), 'sld')";
            if eval "(!t.FROM_INVALID && from_domain_sld != from_name_sld) ||
                     (!is_empty(envelope.from) && envfrom_domain_sld != from_name_sld) ||
                     (is_empty(envelope.from) && helo_domain_sld != from_name_sld)" {
                let "t.SPOOF_DISPLAY_NAME" "1";
            } else {
                let "t.FROM_NEQ_DISPLAY_NAME" "1";
            }
        } else {
            if eval "contains(from_name, 'mr. ') || contains(from_name, 'ms. ') || contains(from_name, 'mrs. ') || contains(from_name, 'dr. ')" {
                let "t.FROM_NAME_HAS_TITLE" "1";
            }
            if eval "contains(header.from.name, '  ')" {
                let "t.FROM_NAME_EXCESS_SPACE" "1";
            }
        }
    }

    if eval "is_empty(envelope.from) && 
             (from_local == 'postmaster' || 
              from_local == 'mailer-daemon' || 
              from_local == 'root')" {
        let "t.FROM_BOUNCE" "1";
    }

    if eval "(!is_empty(envelope.from) && 
               eq_ignore_case(from_addr, envelope.from)) ||
             (t.FROM_BOUNCE && 
              !is_empty(from_domain) && 
              from_domain_sld == helo_domain_sld)" {
        let "t.FROM_EQ_ENVFROM" "1";
    } elsif eval "!t.FROM_INVALID" {
        let "t.FORGED_SENDER" "1";
        let "t.FROM_NEQ_ENVFROM" "1";
    }

    if eval "contains(from_local, '+')" {
        let "t.TAGGED_FROM" "1";
    }

    if eval "count(recipients_to) + count(recipients_cc) == 1" {
        if eval "eq_ignore_case(recipients_to[0], from_addr)" {
            let "t.TO_EQ_FROM" "1";
        } elsif eval "eq_ignore_case(email_part(recipients_to[0], 'domain'), from_domain)" {
            let "t.TO_DOM_EQ_FROM_DOM" "1";
        }
    }

    if eval "!is_ascii(from_raw)" {
        if eval "!env.param.smtputf8 && env.param.body != '8bitmime' && env.param.body != 'binarymime'" {
            let "t.FROM_NEEDS_ENCODING" "1";
        }
        if eval "!is_header_utf8_valid('From')" {
            let "t.INVALID_FROM_8BIT" "1";
        }
    }

    if eval "is_ascii(header.from) && contains(from_raw, '=?') && contains(from_raw, '?=')" {
        if eval "contains(from_raw, '?q?')" {
            # From header is unnecessarily encoded in quoted-printable
            let "t.FROM_EXCESS_QP" "1";
        } elsif eval "contains(from_raw, '?b?')" {
            # From header is unnecessarily encoded in base64
            let "t.FROM_EXCESS_BASE64" "1";
        }
    }

    if eval "!is_empty(from_name) && !is_empty(from_addr) && !contains(from_raw, ' <')" {
        let "t.R_NO_SPACE_IN_FROM" "1";
    }

    # Read confirmation address is different to from address
    let "crt" "header.X-Confirm-Reading-To.addr";
    if eval "!is_empty(crt) && !eq_ignore_case(from_addr, crt)" {
        let "t.HEADER_RCONFIRM_MISMATCH" "1";
    }
} else {
    let "t.MISSING_FROM" "1";
}

if eval "!is_empty(envelope.from)" {
    if eval "is_email(envelope.from)" {
        if eval "contains(service_accounts, envfrom_local)" {
            let "t.ENVFROM_SERVICE_ACCT" "1";
        }
    } else {
        let "t.ENVFROM_INVALID" "1";
    }

    if eval "!is_empty(envfrom_domain_sld)" {
        if eval "lookup('spam/free-domains', envfrom_domain_sld)" {
            let "t.FREEMAIL_ENVFROM" "1";
        } elsif eval "lookup('spam/disposable-domains', envfrom_domain_sld)" {
            let "t.DISPOSABLE_ENVFROM" "1";
        }

        # Mail from no resolve to A or MX
        if eval "!dns_exists(envfrom_domain, 'mx') && !dns_exists(envfrom_domain, 'ip')" {
            let "t.FROMHOST_NORES_A_OR_MX" "1";
        }        
    }

    # Read confirmation address is different to return path
    let "dnt" "header.Disposition-Notification-To.addr";
    if eval "!is_empty(dnt) && !eq_ignore_case(envelope.from, dnt)" {
        let "t.HEADER_FORGED_MDN" "1";
    }
}

if eval "!t.FROM_SERVICE_ACCT && 
         (contains_ignore_case(service_accounts, email_part(rto_addr, 'local')) || 
          contains_ignore_case(service_accounts, email_part(header.sender.addr, 'local')))" {
    let "t.FROM_SERVICE_ACCT" "1";
}

if eval "!t.WWW_DOT_DOMAIN && 
         (contains_ignore_case(rto_addr, '@www.') || 
          contains_ignore_case(header.sender.addr, '@www.'))" {
    let "t.WWW_DOT_DOMAIN" "1";
}

