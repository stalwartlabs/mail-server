
let "message_ids" "header.In-Reply-To:References";

let "i" "count(message_ids)";
while "i > 0" {
    let "i" "i - 1";

    if eval "key_exists(SPAM_DB, 'm:' + message_ids[i])" {
        let "t.TRUSTED_REPLY" "1";
        break;
    }
}
