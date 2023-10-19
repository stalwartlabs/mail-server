# Obtain sender address and domain
let "rep_from" "envelope.from";
let "rep_from_domain" "envfrom_domain_sld";
if eval "is_empty(rep_from)" {
    let "rep_from" "from_addr";
    let "rep_from_domain" "from_domain_sld";
}
if eval "env.dmarc.result != 'pass'" {
    # Do not penalize forged domains
    let "rep_from" "'_' + rep_from";
    let "rep_from_domain" "'_' + rep_from_domain";
}

# Lookup ASN
let "asn" "";
if eval "len(env.remote_ip.reverse) <= 15" {
    let "asn" "env.remote_ip.reverse + '.origin.asn.cymru.com'";
} else {
    let "asn" "env.remote_ip.reverse + '.origin.asn6.cymru.com'";
}
let "asn" "split(dns_query(asn, 'txt'), '|')[0]";

# Generate reputation tokens
let "token_ids" "";
if eval "asn > 0" {
    let "token_ids" "['i:' + env.remote_ip, 'f:' + rep_from, 'd:' + rep_from_domain, 'a:' + asn ]";
} else {
    let "token_ids" "['i:' + env.remote_ip, 'f:' + rep_from, 'd:' + rep_from_domain ]";
}

# Lookup reputation
let "i" "len(token_ids)";
let "reputation" "0.0";

while "i > 0" {
    let "i" "i - 1";
    let "token_id" "token_ids[i]";

    # Lookup reputation
    let "token_rep" "lookup_map('spamdb/reputation-lookup', token_id)";

    # Update reputation
    eval "lookup_map('spamdb/reputation-insert', [token_id, score])";

    if eval "is_empty(token_rep)" {
        continue;
    }

    # Assign weight
    let "weight" "";
    if eval "starts_with(token_id, 'f:')" {
        # Sender address has 50% weight
        let "weight" "0.5";
    } elsif eval "starts_with(token_id, 'd:')" {
        # Sender domain has 20% weight
        let "weight" "0.2";
    } elsif eval "starts_with(token_id, 'i:')" {
        # IP has 20% weight
        let "weight" "0.2";
    } elsif eval "starts_with(token_id, 'a:')" {
        # ASN has 10% weight
        let "weight" "0.1";
    } else {
        continue;
    }

    let "reputation" "reputation + (token_rep[0] / token_rep[1] * weight)";
}

# Adjust score using a 0.5 factor
if eval "reputation > 0" {
    let "score" "score + (reputation - score) * 0.5";
}
