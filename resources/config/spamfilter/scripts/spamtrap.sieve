
# Check if the message was sent to a spam trap address
if eval "AUTOLEARN_ENABLE && lookup('spam/trap-address', envelope.to)" {
    eval "bayes_is_balanced('spamdb/token-lookup', false, AUTOLEARN_SPAM_HAM_BALANCE) && bayes_train('spamdb/token-insert', body_and_subject, true)";
    let "t.SPAM_TRAP" "1";

    # Disable autolearn so the classifier is not trained twice
    let "AUTOLEARN_ENABLE" "0";
}
