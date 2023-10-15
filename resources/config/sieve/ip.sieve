# Reverse ip checks
if eval "env.iprev.result != ''" {
    if eval "ends_with(env.iprev.result, 'error')" {
        let "t.RDNS_DNSFAIL" "1";
    } elsif eval "env.iprev.result == 'fail'" {
        let "t.RDNS_NONE" "1";
    }
}
