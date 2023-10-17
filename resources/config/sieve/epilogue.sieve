
# Train the bayes classifier automatically
if eval "AUTOLEARN_ENABLE && (score >= AUTOLEARN_SPAM_THRESHOLD || score <= AUTOLEARN_HAM_THRESHOLD)" {
    let "is_spam" "score >= AUTOLEARN_SPAM_THRESHOLD";
    eval "bayes_is_balanced('spamdb/token-lookup', is_spam, AUTOLEARN_SPAM_HAM_BALANCE) && 
          bayes_train('spamdb/token-insert', body_and_subject, is_spam)";
}

add balance

# Iterate over tags
let "tags" "var_names()";
let "i" "count(tags)";
let "spam_result" "";
while "i > 0" {
    let "i" "i - 1";
    let "tag" "tags[i]";
    let "tag_score" "map('spam/scores', tag)";

    if eval "is_number(tag_score)" {
        let "score" "score + tag_score";
        if eval "ADD_HEADER_SPAM_RESULT" {
            if eval "!is_empty(spam_result)" {
                let "spam_result" "spam_result + ',\r\n\t' + tag + ' (' + tag_score + ')'";
            } else {
                let "spam_result" "spam_result + tag + ' (' + tag_score + ')'";
            }
        }
    } elsif eval "tag_score == 'reject' {
        let "SCORE_REJECT_THRESHOLD" "1";
        let "score" "2";
        break;
    } else if eval "tag_score == 'discard'" {
        discard;
        stop;
    }
}

# Process score actions
if "SCORE_REJECT_THRESHOLD && score >= SCORE_REJECT_THRESHOLD" {
    reject "Your message has been rejected because it has an excessive spam score. If you feel this is an error, please contact the postmaster.";
    stop;
} else if "SCORE_DISCARD_THRESHOLD && score >= SCORE_DISCARD_THRESHOLD" {
    discard;
    stop;
} else if "ADD_HEADER_SPAM" {
    let "spam_status" "";
    if eval "score >= SCORE_SPAM_THRESHOLD" {
        let "spam_status" "'Yes, score=' + score";
    } else {
        let "spam_status" "'No, score=' + score";
    }
    eval "add-header('X-Spam-Status', spam_status)";
    if eval "!is_empty(spam_result)" {
        eval "add-header('X-Spam-Result', spam_result)";
    }
}

