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

let "i" "0";
let "tls_count" "0";
let "rcvd_from_ip" "0";
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

    if eval "!is_empty(received_part(i, 'from.ip'))" {
        # Received from an IP address rather than a FQDN
        let "rcvd_from_ip" "rcvd_from_ip + 1";
    }

    if eval "!is_empty(received_part(i, 'tls'))" {
        # Received with TLS
        let "tls_count" "tls_count + 1";
    }
}

if eval "rcvd_from_ip >= 2 || (rcvd_from_ip == 1 && is_ip_addr(env.helo_domain))" {
    # Has two or more Received headers containing bare IP addresses
    let "t.RCVD_DOUBLE_IP_SPAM" "1";
}

if eval "rcvd_count == 0" {
    # One received header in a message (currently zero but one header will be added later by the MTA)
    let "t.ONCE_RECEIVED" "1";
    
    # Message has been directly delivered from MUA to local MX
    if eval "header.User-Agent.exists || header.X-Mailer.exists" {
        let "t.DIRECT_TO_MX" "1";
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
