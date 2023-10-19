
# This script should be used on authenticated SMTP sessions only
let "message_id" "header.Message-ID";

if eval "!is_empty(message_id)" {
    # Store the message ID for 30 days
    eval "lookup_map('spamdb/id-insert', [message_id, 2592000])";

    if eval "AUTOLEARN_ENABLE && AUTOLEARN_REPLIES_HAM && bayes_is_balanced('spamdb/token-lookup', false, AUTOLEARN_SPAM_HAM_BALANCE)" {
        eval "bayes_train('spamdb/token-insert', thread_name(header.subject) + ' ' + body.to_text, false)";
    }
}
