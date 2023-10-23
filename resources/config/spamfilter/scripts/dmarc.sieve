if eval "env.spf.result == 'pass'" {
    let "t.SPF_ALLOW" "1";
} elsif eval "env.spf.result == 'fail'" {
    let "t.SPF_FAIL" "1";
} elsif eval "env.spf.result == 'softfail'" {
    let "t.SPF_SOFTFAIL" "1";
} elsif eval "env.spf.result == 'neutral'" {
    let "t.SPF_NEUTRAL" "1";
} elsif eval "env.spf.result == 'temperror'" {
    let "t.SPF_DNSFAIL" "1";
} elsif eval "env.spf.result == 'permerror'" {
    let "t.SPF_PERMFAIL" "1";
} else {
    let "t.SPF_NA" "1";
}

if eval "env.dkim.result == 'pass'" {
    let "t.DKIM_ALLOW" "1";
} elsif eval "env.dkim.result == 'fail'" {
    let "t.DKIM_REJECT" "1";
} elsif eval "env.dkim.result == 'temperror'" {
    let "t.DKIM_TEMPFAIL" "1";
} elsif eval "env.dkim.result == 'permerror'" {
    let "t.DKIM_PERMFAIL" "1";
} else {
    let "t.DKIM_NA" "1";
}

if eval "env.arc.result == 'pass'" {
    let "t.ARC_ALLOW" "1";
} elsif eval "env.arc.result == 'fail'" {
    let "t.ARC_REJECT" "1";
} elsif eval "env.arc.result == 'temperror'" {
    let "t.ARC_DNSFAIL" "1";
} elsif eval "env.arc.result == 'permerror'" {
    let "t.ARC_INVALID" "1";
} else {
    let "t.ARC_NA" "1";
}

if eval "env.dmarc.result == 'pass'" {
    let "t.DMARC_POLICY_ALLOW" "1";
} elsif eval "env.dmarc.result == 'temperror'" {
    let "t.DMARC_DNSFAIL" "1";
} elsif eval "env.dmarc.result == 'permerror'" {
    let "t.DMARC_BAD_POLICY" "1";
} elsif eval "env.dmarc.result == 'fail'" {
    if eval "env.dmarc.policy == 'quarantine'" {
        let "t.DMARC_POLICY_QUARANTINE" "1";
    } elsif eval "env.dmarc.policy == 'reject'" {
        let "t.DMARC_POLICY_REJECT" "1";
    } else {
        let "t.DMARC_POLICY_SOFTFAIL" "1";
    }
} else {
    let "t.DMARC_NA" "1";
}

if eval "header.DKIM-Signature.exists" {
    let "t.DKIM_SIGNED" "1";
    if eval "header.ARC-Seal.exists" {
        let "t.ARC_SIGNED" "1";
    }
}

# Check allowlists
if eval "lookup('spam/dmarc-allow', from_domain)" {
    if eval "t.DMARC_POLICY_ALLOW" {
        let "t.ALLOWLIST_DMARC" "1";
    } else {
        let "t.BLOCKLIST_DMARC" "1";
    }
} elsif eval "lookup('spam/spf-dkim-allow', from_domain)" {
    let "is_dkim_pass" "contains(env.dkim.domains, from_domain) || t.ARC_ALLOW";

    if eval "is_dkim_pass && t.SPF_ALLOW" {
        let "t.ALLOWLIST_SPF_DKIM" "1";
    } elsif eval "is_dkim_pass" {
        let "t.ALLOWLIST_DKIM" "1";
        if eval "!t.SPF_DNSFAIL" {
            let "t.BLOCKLIST_SPF" "1";
        }
    } elsif eval "t.SPF_ALLOW" {
        let "t.ALLOWLIST_SPF" "1";
        if eval "!t.DKIM_TEMPFAIL" {
            let "t.BLOCKLIST_DKIM" "1";
        }
    } elsif eval "!t.SPF_DNSFAIL && !t.DKIM_TEMPFAIL" {
        let "t.BLOCKLIST_SPF_DKIM" "1";
    }
}
