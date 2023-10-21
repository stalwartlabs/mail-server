if eval "!is_ip_addr(env.helo_domain)" {
    let "helo" "env.helo_domain";

    if eval "contains(helo, '.')" {
        if eval "!is_empty(env.iprev.ptr) && !eq_ignore_case(helo, env.iprev.ptr)" {
            # Helo does not match reverse IP
            let "t.HELO_IPREV_MISMATCH" "1";
        }
        if eval "!dns_exists(helo, 'ip') && !dns_exists(helo, 'mx')" {
            # Helo no resolve to A or MX
            let "t.HELO_NORES_A_OR_MX" "1";
        }
    } else {
        if eval "contains(helo, 'user')" {
            # HELO contains 'user'
            let "t.RCVD_HELO_USER" "1";
        }

        # Helo not FQDN
        let "t.HELO_NOT_FQDN" "1";
    }
} else {
    # Helo host is bare ip
    let "t.HELO_BAREIP" "1";
    
    if eval "env.helo_domain != env.remote_ip" {
        # Helo A IP != hostname IP
        let "t.HELO_IP_A" "1";
    }
}
