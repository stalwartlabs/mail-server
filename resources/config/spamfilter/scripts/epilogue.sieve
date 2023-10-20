
# Train the bayes classifier automatically
if eval "AUTOLEARN_ENABLE && (score >= AUTOLEARN_SPAM_THRESHOLD || score <= AUTOLEARN_HAM_THRESHOLD)" {
    let "is_spam" "score >= AUTOLEARN_SPAM_THRESHOLD";
    eval "bayes_is_balanced('spamdb/token-lookup', is_spam, AUTOLEARN_SPAM_HAM_BALANCE) && 
          bayes_train('spamdb/token-insert', body_and_subject, is_spam)";
}

# Process score actions
if eval "SCORE_REJECT_THRESHOLD && score >= SCORE_REJECT_THRESHOLD" {
    reject "Your message has been rejected because it has an excessive spam score. If you feel this is an error, please contact the postmaster.";
    stop;
} elsif eval "SCORE_DISCARD_THRESHOLD && score >= SCORE_DISCARD_THRESHOLD" {
    discard;
    stop;
} elsif eval "ADD_HEADER_SPAM" {
    let "spam_status" "";
    if eval "score >= SCORE_SPAM_THRESHOLD" {
        let "spam_status" "'Yes, score=' + score";
    } else {
        let "spam_status" "'No, score=' + score";
    }
    eval "add_header('X-Spam-Status', spam_status)";
    if eval "!is_empty(spam_result)" {
        eval "add_header('X-Spam-Result', spam_result)";
    }
}

