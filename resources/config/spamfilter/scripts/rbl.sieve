
# Validate IP addresses
let "ip_addresses" "dedup(winnow([ env.remote_ip ] + header.received[*].rcvd.ip + header.received[*].rcvd.from.ip + header.received[*].rcvd.by.ip))";
let "ip_addresses_len" "count(ip_addresses)";
let "i" "0";

while "i < ip_addresses_len" {
    let "ip_address" "ip_addresses[i]";
    let "is_from_addr" "i == 0";
    let "i" "i + 1";

    if eval "ip_address == '127.0.0.1' || ip_address == '::1'" {
        continue;
    }

    # Do not check more than 10 IP addresses
    if eval "i >= 10" {
        break;
    }

    let "ip_reverse" "ip_reverse_name(ip_address)";
    let "is_ip_v4" "len(ip_reverse) <= 15";

    # Query SPAMHAUS
    let "result" "rsplit_once(dns_query(ip_reverse + '.zen.spamhaus.org', 'ipv4')[0], '.')";
    if eval "result[0] == '127.0.0'" {
        let "result" "result[1]";

        if eval "result == 2" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_SBL" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_SBL" "1";
            }
        } elsif eval "result == 3" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_CSS" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_CSS" "1";
            }
        } elsif eval "result >= 4 && result <= 7" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_XBL" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_XBL" "1";
            }
        } elsif eval "result == 9" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_DROP" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_PBL" "1";
            }
        } elsif eval "result == 10 || result == 11" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_PBL" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_PBL" "1";
            }
        } elsif eval "result == 254" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_BLOCKED_OPENRESOLVER" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER" "1";
            }
        } elsif eval "result == 255" {
            if eval "is_from_addr" {
                let "t.RBL_SPAMHAUS_BLOCKED" "1";
            } else {
                let "t.RECEIVED_SPAMHAUS_BLOCKED" "1";
            }
        } else {
            # Unrecognized result
            let "t.RBL_SPAMHAUS" "1";
        }
    }

    if eval "is_from_addr" {
        # Query IP reputation at Mailspike
        let "result" "rsplit_once(dns_query(ip_reverse + '.rep.mailspike.net', 'ipv4')[0], '.')";
        if eval "result[0] == '127.0.0'" {
            let "result" "result[1]";

            if eval "result == 10" {
                let "t.RBL_MAILSPIKE_WORST" "1";
            } elsif eval "result == 11" {
                let "t.RBL_MAILSPIKE_VERYBAD" "1";
            } elsif eval "result == 12" {
                let "t.RBL_MAILSPIKE_BAD" "1";
            } elsif eval "result >= 13 && result <= 16" {
                let "t.RWL_MAILSPIKE_NEUTRAL" "1";
            } elsif eval "result == 17" {
                let "t.RWL_MAILSPIKE_POSSIBLE" "1";
            } elsif eval "result == 18" {
                let "t.RWL_MAILSPIKE_GOOD" "1";
            } elsif eval "result == 19" {
                let "t.RWL_MAILSPIKE_VERYGOOD" "1";
            } elsif eval "result == 20" {
                let "t.RWL_MAILSPIKE_EXCELLENT" "1";
            }  
        }

        # Query SenderScore
        if eval "dns_exists(ip_reverse + '.bl.score.senderscore.com', 'ipv4')" {
            let "t.RBL_SENDERSCORE" "1";
        }

        # Query SpamEatingMonkey
        if eval "is_ip_v4 && dns_exists(ip_reverse + '.bl.spameatingmonkey.net', 'ipv4')" {
            let "t.RBL_SEM" "1";
        } elsif eval "!is_ip_v4 && dns_exists(ip_reverse + '.bl.ipv6.spameatingmonkey.net', 'ipv4')" {
            let "t.RBL_SEM_IPV6" "1";
        }

        # Query VirusFree
        if eval "dns_query(ip_reverse + '.bip.virusfree.cz', 'ipv4')[0] == '127.0.0.2'" {
            let "t.RBL_VIRUSFREE_BOTNET" "1";
        }

        # Query NiX
        if eval "dns_exists(ip_reverse + '.ix.dnsbl.manitu.net', 'ipv4')" {
            let "t.RBL_NIXSPAM" "1";
        }

        # Query Spamcop
        if eval "dns_exists(ip_reverse + '.bl.spamcop.net', 'ipv4')" {
            let "t.RBL_SPAMCOP" "1";
        }

        # Query Barracuda
        if eval "dns_exists(ip_reverse + '.b.barracudacentral.org', 'ipv4')" {
            let "t.RBL_BARRACUDA" "1";
        }
    }

    # Query Blocklist.de
    if eval "dns_exists(ip_reverse + '.bl.blocklist.de', 'ipv4')" {
        if eval "is_from_addr" {
            let "t.RBL_BLOCKLISTDE" "1";
        } else {
            let "t.RECEIVED_BLOCKLISTDE" "1";
        }
    }

    # Query DNSWL
    let "result" "rsplit_once(dns_query(ip_reverse + '.list.dnswl.org', 'ipv4')[0], '.')";
    if eval "starts_with(result[0], '127.')" {
        let "result" "result[1]";

        if eval "result == 0" {
            let "t.RCVD_IN_DNSWL_NONE" "1";
        } elsif eval "result == 1" {
            let "t.RCVD_IN_DNSWL_LOW" "1";
        } elsif eval "result == 2" {
            let "t.RCVD_IN_DNSWL_MED" "1";
        } elsif eval "result == 3" {
            let "t.RCVD_IN_DNSWL_HI" "1";
        } elsif eval "result == 255" {
            let "t.DNSWL_BLOCKED" "1";
        }
    }
}

# Validate domain names
let "emails" "dedup(winnow(to_lowercase([from_addr, rto_addr, envelope.from] + tokenize(text_body, 'email'))))";
let "emails_len" "count(emails)";
let "domains" "dedup(winnow(to_lowercase([ env.helo_domain, env.iprev.ptr ] + email_part(emails, 'domain') + puny_decode(uri_part(urls, 'host')))))";
let "domains_len" "count(domains)";
let "i" "0";

while "i < domains_len" {
    let "domain" "domains[i]";
    let "i" "i + 1";

    # Skip invalid and local domain names
    if eval "!contains(domain, '.') || 
             is_ip_addr(domain) || 
             is_local_domain(DOMAIN_DIRECTORY, domain_part(domain, 'sld')) ||
             lookup('spam/domains-allow', domain)" {
        continue;
    }

    # Do not check more than 10 domain names
    if eval "i >= 10" {
        break;
    }

    # Query SpamHaus DBL
    let "result" "rsplit_once(dns_query(domain + '.dbl.spamhaus.org', 'ipv4')[0], '.')";
    if eval "result[0] == '127.0.0'" {
        let "result" "result[1]";

        if eval "result == 2" {
            let "t.DBL_SPAM" "";
        } elsif eval "result == 4" {
            let "t.DBL_PHISH" "1";
        } elsif eval "result == 5" {
            let "t.DBL_MALWARE" "1";
        } elsif eval "result == 6" {
            let "t.DBL_BOTNET" "1";
        } elsif eval "result == 102" {
            let "t.DBL_ABUSE" "1";
        } elsif eval "result == 103" {
            let "t.DBL_ABUSE_REDIR" "1";
        } elsif eval "result == 104" {
            let "t.DBL_ABUSE_PHISH" "1";
        } elsif eval "result == 105" {
            let "t.DBL_ABUSE_MALWARE" "1";
        } elsif eval "result == 106" {
            let "t.DBL_ABUSE_BOTNET" "1";
        } elsif eval "result == 254" {
            let "t.DBL_BLOCKED_OPENRESOLVER" "1";
        } elsif eval "result == 255" {
            let "t.DBL_BLOCKED" "1";
        }  
    }

    # Query SURBL multi
    let "result" "rsplit_once(dns_query(domain + '.multi.surbl.org', 'ipv4')[0], '.')";
    if eval "result[0] == '127.0.0'" {
        let "result" "result[1]";

        if eval "result == 128" {
            let "t.CRACKED_SURBL" "1";
        } elsif eval "result == 64" {
            let "t.ABUSE_SURBL" "1";
        } elsif eval "result == 16" {
            let "t.MW_SURBL_MULTI" "1";
        } elsif eval "result == 8" {
            let "t.PH_SURBL_MULTI" "1";
        } elsif eval "result == 1" {
            let "t.SURBL_BLOCKED" "1";
        }  
    }    

    # Query URIBL multi
    let "result" "rsplit_once(dns_query(domain + '.multi.uribl.com', 'ipv4')[0], '.')";
    if eval "result[0] == '127.0.0'" {
        let "result" "result[1]";

        if eval "result == 1" {
            let "t.URIBL_BLOCKED" "1";
        } elsif eval "result == 2" {
            let "t.URIBL_BLACK" "1";
        } elsif eval "result == 4" {
            let "t.URIBL_GREY" "1";
        } elsif eval "result == 8" {
            let "t.URIBL_RED" "1";
        }  
    }

    # Query SpamEatingMonkey URIBL
    if eval "dns_query(domain + '.uribl.spameatingmonkey.net', 'ipv4')[0] == '127.0.0.2'" {
        let "t.SEM_URIBL" "1";
    }

    # Query SpamEatingMonkey FRESH15
    if eval "dns_query(domain + '.fresh15.spameatingmonkey.net', 'ipv4')[0] == '127.0.0.2'" {
        let "t.SEM_URIBL_FRESH15" "1";
    }

}

# Check DKIM domains that passed validation
let "i" "count(env.dkim.domains)";
while "i > 0" {
    let "i" "i - 1";

    # Query DNSWL
    let "result" "rsplit_once(dns_query(env.dkim.domains[i] + '.dwl.dnswl.org', 'ipv4')[0], '.')";
    if eval "starts_with(result[0], '127.')" {
        let "result" "result[1]";

        if eval "result == 0" {
            let "t.DWL_DNSWL_NONE" "1";
        } elsif eval "result == 1" {
            let "t.DWL_DNSWL_LOW" "1";
        } elsif eval "result == 2" {
            let "t.DWL_DNSWL_MED" "1";
        } elsif eval "result == 3" {
            let "t.DWL_DNSWL_HI" "1";
        } elsif eval "result == 255" {
            let "t.DWL_DNSWL_BLOCKED" "1";
        }  
    }    
}

# Validate email addresses
let "i" "0";
while "i < emails_len" {
    let "email" "emails[i]";
    let "i" "i + 1";

    # Skip invalid and local e-mail addresses
    if eval "!contains(email, '@') || is_local_domain(DOMAIN_DIRECTORY, domain_part(email_part(email, 'domain'), 'sld'))" {
        continue;
    }

    # Do not check more than 10 email addresses
    if eval "i >= 10" {
        break;
    }

    # Query MSBL EBL
    let "result" "rsplit_once(dns_query(hash(email, 'sha1') + '.ebl.msbl.org', 'ipv4')[0], '.')";
    if eval "result[1] == 2 || result[1] == 3" {
        if eval "result[0] == '127.0.0'" {
            let "t.MSBL_EBL" "1";
        } elsif eval "result[0] == '127.0.1'" {
            let "t.MSBL_EBL_GREY" "1";
        }  
    }
}


# Validate URL hashes
let "i" "0";
let "urls_len" "count(urls)";
while "i < urls_len" {
    let "url" "urls[i]";
    let "i" "i + 1";

    # Do not check more than 10 URLs
    if eval "i >= 10" {
        break;
    }

    # Skip URLs pointing to local or trusted domains
    let "domain" "domain_part(uri_part(url, 'host'), 'sld')";
    if eval "is_local_domain(DOMAIN_DIRECTORY, domain) ||
             lookup('spam/domains-allow', domain)" {
        continue;
    }

    # Query SURBL HASHBL
    let "result" "rsplit_once(dns_query(hash(url, 'md5') + '.hashbl.surbl.org', 'ipv4')[0], '.')";
    if eval "starts_with(result[0], '127.0.')" {
        let "result" "result[1]";

        if eval "result == 8" {
            let "t.SURBL_HASHBL_PHISH" "1";
        } elsif eval "result == 16" {
            let "t.SURBL_HASHBL_MALWARE" "1";
        } elsif eval "result == 64" {
            let "t.SURBL_HASHBL_ABUSE" "1";
        } elsif eval "result == 128" {
            let "t.SURBL_HASHBL_CRACKED" "1";
        } elsif eval "result[0] == '127.0.1'" {
            let "t.SURBL_HASHBL_EMAIL" "1";
        }  
    }
}
