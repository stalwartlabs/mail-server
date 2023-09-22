set "rcvd_raw" "%{header.received[*].raw}";
set "rcvd_count" "%{count(rcvd_raw)}";

# Count received headers
if eval "rcvd_count == 0" {
    set "t.RCVD_COUNT_ZERO" "1";
} elsif eval "rcvd_count == 1" {
    set "t.RCVD_COUNT_ONE" "1";
} elsif eval "rcvd_count == 2" {
    set "t.RCVD_COUNT_TWO" "1";
} elsif eval "rcvd_count == 3" {
    set "t.RCVD_COUNT_THREE" "1";
} elsif eval "rcvd_count <= 5" {
    set "t.RCVD_COUNT_FIVE" "1";
} elsif eval "rcvd_count <= 7" {
    set "t.RCVD_COUNT_SEVEN" "1";
} elsif eval "rcvd_count <= 12" {
    set "t.RCVD_COUNT_TWELVE" "1";
}

# Received from an authenticated user
if eval "!is_empty(env.authenticated_as)" {
    set "t.RCVD_VIA_SMTP_AUTH" "1";
}

# Received headers have non-ASCII characters
if eval "!is_ascii(rcvd_raw)" {
    set "t.RCVD_ILLEGAL_CHARS" "1";
}

# HELO contains 'user'
if eval "eq_ignore_case(env.helo_domain, 'user')" {
    set "t.RCVD_HELO_USER" "1";
}

# Received from an IP address rather than a FQDN
if eval "is_ip_addr(env.helo_domain)" {
    set "t.RCVD_IP_SPAM" "1";
}

# Received: HELO and IP do not match, but should
if eval "!is_empty(env.iprev.ptr) && !eq_ignore_case(env.helo_domain, env.iprev.ptr)" {
    set "t.RCVD_HELO_IP_MISMATCH" "1";
}

set "i" "0";
set "recipients" "%{header.to[*].addr[*]}";
set "tls_count" "0";
while "i < rcvd_count" {
    set "i" "%{i + 1}";
    set "helo_domain" "%{received_part(i, 'from')}";

    # Check for a forged received trail
    if eval "!t.FORGED_RCVD_TRAIL" {
        set "iprev" "%{received_part(i, 'iprev')}";

        if eval "!is_empty(iprev) && !is_empty(helo_domain) && !eq_ignore_case(helo_domain, iprev)" {
            set "t.FORGED_RCVD_TRAIL" "1";
        }
    }

    if eval "!t.PREVIOUSLY_DELIVERED" {
        set "for" "%{received_part(i, 'for')}";
        # Recipient appears on Received trail
        if eval "!is_empty(for) && contains_ignore_case(recipients, for)" {
            set "t.PREVIOUSLY_DELIVERED" "1";
        }
    }

    if eval "!t.RCVD_HELO_USER && eq_ignore_case(helo_domain, 'user')" {
        # Received: HELO contains 'user'
        set "t.RCVD_HELO_USER" "1";
    }

    if eval "!t.RCVD_IP_SPAM && !is_empty(received_part(i, 'from.ip'))" {
        # Received from an IP address rather than a FQDN
        set "t.RCVD_IP_SPAM" "1";
    }

    if eval "!is_empty(received_part(i, 'tls'))" {
        # Received with TLS
        set "tls_count" "%{tls_count + 1}";
    }
}

# Received with TLS checks
if eval "rcvd_count > 0 && tls_count == rcvd_count && !is_empty(env.tls.version)" {
    set "t.RCVD_TLS_ALL" "1";
} elsif eval "!is_empty(env.tls.version)" {
    set "t.RCVD_TLS_LAST" "1";
} else {
    set "t.RCVD_NO_TLS_LAST" "1";
}
