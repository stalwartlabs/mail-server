# Add scores
let "tags" "var_names()";
let "i" "count(tags)";
let "spam_result" "";
while "i > 0" {
    let "i" "i - 1";
    let "tag" "tags[i]";
    let "tag_score" "lookup_map('spam/scores', tag)";

    if eval "is_number(tag_score)" {
        let "score" "score + tag_score";
        if eval "ADD_HEADER_SPAM_RESULT" {
            if eval "!is_empty(spam_result)" {
                let "spam_result" "spam_result + ',\r\n\t' + tag + ' (' + tag_score + ')'";
            } else {
                let "spam_result" "spam_result + tag + ' (' + tag_score + ')'";
            }
        }
    } elsif eval "tag_score == 'reject'" {
        let "SCORE_REJECT_THRESHOLD" "1";
        let "score" "2";
        break;
    } elsif eval "tag_score == 'discard'" {
        discard;
        stop;
    }
}
