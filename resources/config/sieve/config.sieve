# Whether to add an X-Spam-Status header
let "ADD_HEADER_SPAM" "true";

# Whether to add an X-Spam-Result header
let "ADD_HEADER_SPAM_RESULT" "true";

# Whether message replies from authenticated users should be learned as ham
let "AUTOLEARN_REPLIES_HAM" "true";

# Whether the bayes classifier should be trained automatically
let "AUTOLEARN_ENABLE" "true";

# When to learn ham (score >= threshold)
let "AUTOLEARN_HAM_THRESHOLD" "-0.5";

# When to learn spam (score <= threshold)
let "AUTOLEARN_SPAM_THRESHOLD" "6.0";

# Keep difference for spam/ham learns for at least this value
let "AUTOLEARN_SPAM_HAM_BALANCE" "0.9";

# If ADD_HEADER_SPAM is enabled, mark as SPAM messages with a score above this threshold
let "SCORE_SPAM_THRESHOLD" "5.0";

# Discard messages with a score above this threshold
let "SCORE_DISCARD_THRESHOLD" "0";

# Reject messages with a score above this threshold
let "SCORE_REJECT_THRESHOLD" "0";

# Directory name to use for local domain lookups
let "DOMAIN_DIRECTORY" "'default'";

