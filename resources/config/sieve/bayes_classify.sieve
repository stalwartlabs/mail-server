if eval "!t.SPAM_TRAP && !t.TRUSTED_REPLY" {
    let "bayes_result" "bayes_classify('spamdb/bayes-classify', body_and_subject)";
    if eval "!is_empty(bayes_result)" {
        if eval "bayes_result > 0.7" {
            let "t.BAYES_SPAM" "1";
        } elsif eval "bayes_result < 0.5" {
            let "t.BAYES_HAM" "1";
        }
    }
}
