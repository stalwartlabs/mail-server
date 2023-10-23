if eval "(count(body_urls) == 1 || count(html_body_urls) == 1) && count(tokenize(text_body, 'words')) == 0" {
    let "t.URL_ONLY" "1";
}

if eval "has_zwsp(urls)" {
    let "t.ZERO_WIDTH_SPACE_URL" "1";
} elsif eval "has_obscured(urls)" {
    let "t.R_SUSPICIOUS_URL" "1";
}

let "i" "count(urls)";
while "i > 0" {
    let "i" "i - 1";
    let "url" "urls[i]";

    # Skip non-URLs such as 'data:' and 'mailto:'
    if eval "!contains(url, '://')" {
        continue;
    }

    let "host" "uri_part(url, 'host')";

    if eval "!is_empty(host)" {
        let "is_ip" "is_ip_addr(host)";
        let "host" "puny_decode(host)";
        let "host_lc" "to_lowercase(host)";
        let "host_sld" "domain_part(host_lc, 'sld')";

        # Skip local and trusted domains
        if eval "is_local_domain(DOMAIN_DIRECTORY, host_sld) || lookup('spam/domains-allow', host_sld)" {
            continue;
        }

        if eval "!is_ip && 
                 (!t.REDIRECTOR_URL || !t.URL_REDIRECTOR_NESTED) && 
                 lookup('spam/redirectors', host_sld)" {
            let "t.REDIRECTOR_URL" "1";
            let "redir_count" "1";

            while "redir_count <= 5" {
                # Use a custom user-agent and a 3 second timeout
                let "url_redirect" "http_header(url, 'Location', 'Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/118.0', 3000)";
                if eval "!is_empty(url_redirect)" {
                    let "url" "url_redirect";
                    let "host" "uri_part(url, 'host')";
                    let "is_ip" "is_ip_addr(host)";
                    let "host" "puny_decode(host)";
                    let "host_lc" "to_lowercase(host)";
                    let "host_sld" "domain_part(host_lc, 'sld')";

                    if eval "!is_ip && lookup('spam/redirectors', host_sld)" {
                        let "redir_count" "redir_count + 1";
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            if eval "redir_count > 5" {
                let "t.URL_REDIRECTOR_NESTED" "1";
            }
        }

        let "url_lc" "to_lowercase(url)";
        let "query" "uri_part(url_lc, 'path_query')";
        if eval "!is_ip" {
            if eval "!is_ascii(host)" {
                let "host_cured" "cure_text(host)";
                if eval "host_lc != host_cured && dns_exists(host_cured, 'ip')" {
                    let "t.HOMOGRAPH_URL" "1";
                }

                if eval "!is_single_script(host)" {
                    let "t.MIXED_CHARSET_URL" "1";
                }
            } else {
                if eval "ends_with(host, 'googleusercontent.com') && starts_with(query, '/proxy/')" {
                    let "t.HAS_GUC_PROXY_URI" "1";
                } elsif eval "ends_with(host, 'firebasestorage.googleapis.com')" {
                    let "t.HAS_GOOGLE_FIREBASE_URL" "1";
                } elsif eval "starts_with(domain_part(host, 'sld'), 'google.') && contains(query, 'url?') " {
                    let "t.HAS_GOOGLE_REDIR" "1";
                }
            }

            if eval "(contains(host_lc, 'ipfs.') || contains(query, '/ipfs')) && contains(query, '/qm')" {
                # InterPlanetary File System (IPFS) gateway URL, likely malicious
                let "t.HAS_IPFS_GATEWAY_URL" "1";
            } elsif eval "ends_with(host_lc, '.onion')" {
                let "t.HAS_ONION_URI" "1";
            }
        } else {
            # URL is an ip address
            let "t.R_SUSPICIOUS_URL" "1";
        }

        if eval "starts_with(query, '/wp-')" {
            # Contains WordPress URIs
            let "t.HAS_WP_URI" "1";
            if eval "starts_with(query, '/wp-content') | starts_with(query, '/wp-includes')" {
                # URL that is pointing to a compromised WordPress installation
                let "t.WP_COMPROMISED" "1";
            }
        }
        if eval "contains(query, '/../') && !contains(query, '/well-known') && !contains(query, '/well_known')" {
            # Message contains URI with a hidden path
            let "t.URI_HIDDEN_PATH" "1";
        }

        # Phishing checks (refresh OpenPhish every 12 hours, PhishTank every 6 hours)
        if eval "lookup_remote('https://openphish.com/feed.txt', url, [43200, 'list'])" {
            let "t.PHISHED_OPENPHISH" "1";
        }
        if eval "lookup_remote('http://data.phishtank.com/data/online-valid.csv', url, [21600, 'csv', 1, ',', true])" {
            let "t.PHISHED_PHISHTANK" "1";
        }

    } else {
        # URL could not be parsed
        let "t.R_SUSPICIOUS_URL" "1";
    }
}

