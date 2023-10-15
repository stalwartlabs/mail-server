
# Check if the message was sent to a spam trap address
if eval "lookup('spam/trap-address', envelope.to)" {
    eval "bayes_train('spamdb/bayes-train', body_and_subject, true)";
    let "t.SPAM_TRAP" "1";
}
