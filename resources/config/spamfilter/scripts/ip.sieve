# Reverse ip checks
if eval "env.iprev.result != ''" {
    if eval "env.iprev.result == 'temperror'" {
        let "t.RDNS_DNSFAIL" "1";
    } elsif eval "env.iprev.result == 'fail' || env.iprev.result == 'permerror'" {
        let "t.RDNS_NONE" "1";
    }
}
