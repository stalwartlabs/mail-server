
# This script should be used on authenticated SMTP sessions only
let "message_id" "header.Message-ID";

if eval "!is_empty(message_id)" {
    eval "lookup('spamdb/id-insert', message_id)";

    if eval "lookup('spam/options', 'AUTOLEARN_REPLIES')" {
        eval "bayes_train('spamdb/bayes-train', thread_name(header.subject) + ' ' + body.to_text, false)";
    }
}
