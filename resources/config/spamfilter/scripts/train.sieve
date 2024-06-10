

# Obtain thread name and subject
let "contents" "thread_name(header.subject) + ' ' + body.to_text";

if eval "env.train == 'spam'" {
    eval "bayes_train(SPAM_DB, contents, true)";
} elsif eval "env.train == 'ham'" {
    eval "bayes_train(SPAM_DB, contents, false)";
} else {
    reject "Missing variable 'train'";
}
