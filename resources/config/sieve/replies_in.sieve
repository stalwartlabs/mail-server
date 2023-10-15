
if eval "lookup('spamdb/id-lookup', header.In-Reply-To:References)" {
    let "t.TRUSTED_REPLY" "1";
}
