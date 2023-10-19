if eval "!t.SPAM_TRAP && !t.TRUSTED_REPLY" {

    # Classification parameters
    # min_token_hits: 2
    # min_tokens: 11
    # min_prob_strength: 0.05
    # min_learns: 200

    let "bayes_result" "bayes_classify('spamdb/token-lookup', body_and_subject, [2, 11, 0.05, 200])";
    if eval "!is_empty(bayes_result)" {
        if eval "bayes_result > 0.7" {
            let "t.BAYES_SPAM" "1";
        } elsif eval "bayes_result < 0.5" {
            let "t.BAYES_HAM" "1";
        }
    }
}
