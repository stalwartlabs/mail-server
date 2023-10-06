# Reverse ip checks
if eval "env.iprev.result != ''" {
    if eval "ends_with(env.iprev.result, 'error')" {
        let "t.RDNS_DNSFAIL" "1";
    } elsif eval "env.iprev.result == 'fail'" {
        let "t.RDNS_NONE" "1";
    }
}

# Lookup ASN
let "asn_lookup" "";
if eval "len(env.remote_ip.reverse) <= 15" {
    let "asn_lookup" "env.remote_ip.reverse + '.origin.asn.cymru.com'";
} else {
    let "asn_lookup" "env.remote_ip.reverse + '.origin.asn6.cymru.com'";
}
let "asn_lookup" "split(dns_query(asn_lookup, 'txt'), '|')";
let "asn" "asn_lookup[0]";
let "country" "asn_lookup[2]";

#eval "print('ASN: ' + asn + ' (' + country + ')')";

