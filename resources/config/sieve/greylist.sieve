
set "triplet" "${env.remote_ip}.${envelope.from}.${envelope.to}";

if eval "!lookup('spamdb/id-lookup', triplet)" {
    # Greylist sender for 30 days
    eval "lookup_map('spamdb/id-insert', [triplet, 2592000])";
    reject "422 4.2.2 Greylisted, please try again in a few moments.";
    stop;
}
