let "rcvd_raw" "header.received[*].raw";
let "rcvd_count" "count(rcvd_raw)";

# Count received headers
if eval "rcvd_count == 0" {
    let "t.RCVD_COUNT_ZERO" "1";
} elsif eval "rcvd_count == 1" {
    let "t.RCVD_COUNT_ONE" "1";
} elsif eval "rcvd_count == 2" {
    let "t.RCVD_COUNT_TWO" "1";
} elsif eval "rcvd_count == 3" {
    let "t.RCVD_COUNT_THREE" "1";
} elsif eval "rcvd_count <= 5" {
    let "t.RCVD_COUNT_FIVE" "1";
} elsif eval "rcvd_count <= 7" {
    let "t.RCVD_COUNT_SEVEN" "1";
} elsif eval "rcvd_count <= 12" {
    let "t.RCVD_COUNT_TWELVE" "1";
}

# Received from an authenticated user
if eval "!is_empty(env.authenticated_as)" {
    let "t.RCVD_VIA_SMTP_AUTH" "1";
}

# Received headers have non-ASCII characters
if eval "!is_ascii(rcvd_raw)" {
    let "t.RCVD_ILLEGAL_CHARS" "1";
}

# HELO contains 'user'
if eval "eq_ignore_case(env.helo_domain, 'user')" {
    let "t.RCVD_HELO_USER" "1";
}

# Received from an IP address rather than a FQDN
if eval "is_ip_addr(env.helo_domain)" {
    let "t.RCVD_IP_SPAM" "1";
}

# Received: HELO and IP do not match, but should
if eval "!is_empty(env.iprev.ptr) && !eq_ignore_case(env.helo_domain, env.iprev.ptr)" {
    let "t.RCVD_HELO_IP_MISMATCH" "1";
}

let "i" "0";
let "recipients" "header.to:cc:bcc[*].addr[*]";
let "tls_count" "0";
while "i < rcvd_count" {
    let "i" "i + 1";
    let "helo_domain" "received_part(i, 'from')";

    # Check for a forged received trail
    if eval "!t.FORGED_RCVD_TRAIL" {
        let "iprev" "received_part(i, 'iprev')";

        if eval "!is_empty(iprev) && !is_empty(helo_domain) && !eq_ignore_case(helo_domain, iprev)" {
            let "t.FORGED_RCVD_TRAIL" "1";
        }
    }

    if eval "!t.PREVIOUSLY_DELIVERED" {
        let "for" "received_part(i, 'for')";
        # Recipient appears on Received trail
        if eval "!is_empty(for) && contains_ignore_case(recipients, for)" {
            let "t.PREVIOUSLY_DELIVERED" "1";
        }
    }

    if eval "!t.RCVD_HELO_USER && eq_ignore_case(helo_domain, 'user')" {
        # Received: HELO contains 'user'
        let "t.RCVD_HELO_USER" "1";
    }

    if eval "!t.RCVD_IP_SPAM && !is_empty(received_part(i, 'from.ip'))" {
        # Received from an IP address rather than a FQDN
        let "t.RCVD_IP_SPAM" "1";
    }

    if eval "!is_empty(received_part(i, 'tls'))" {
        # Received with TLS
        let "tls_count" "tls_count + 1";
    }
}

# Received with TLS checks
if eval "rcvd_count > 0 && tls_count == rcvd_count && !is_empty(env.tls.version)" {
    let "t.RCVD_TLS_ALL" "1";
} elsif eval "!is_empty(env.tls.version)" {
    let "t.RCVD_TLS_LAST" "1";
} else {
    let "t.RCVD_NO_TLS_LAST" "1";
}
