if eval "!is_ip_addr(env.helo_domain)" {
    let "helo" "env.helo_domain";

    if eval "contains(helo, '.')" {
        if eval "!is_empty(env.iprev.ptr) && !eq_ignore_case(helo, env.iprev.ptr)" {
            # Unknown client hostname (PTR or FCrDNS verification failed)
            let "t.HFILTER_HOSTNAME_UNKNOWN" "1";
        }
        if eval "!dns_exists(helo, 'ip') && !dns_exists(helo, 'mx')" {
            # Helo no resolve to A or MX
            let "t.HFILTER_HELO_NORES_A_OR_MX" "1";
        }
    } else {
        if eval "contains(helo, 'user')" {
            # HELO contains 'user'
            let "t.RCVD_HELO_USER" "1";
        }

        # Helo not FQDN
        let "t.HFILTER_HELO_NOT_FQDN" "1";
    }
} else {
    # Helo host is bare ip
    let "t.HFILTER_HELO_BAREIP" "1";
    
    if eval "env.helo_domain != env.remote_ip" {
        # Helo A IP != hostname IP
        let "t.HFILTER_HELO_IP_A" "1";
    }
}
