# Whether to add an X-Spam-Status header
let "ADD_HEADER_SPAM" "key_get('spam-config', 'add-spam')";

# Whether to add an X-Spam-Result header
let "ADD_HEADER_SPAM_RESULT" "key_get('spam-config', 'add-spam-result')";

# Whether message replies from authenticated users should be learned as ham
let "AUTOLEARN_REPLIES_HAM" "key_get('spam-config', 'learn-ham-replies')";

# Whether the bayes classifier should be trained automatically
let "AUTOLEARN_ENABLE" "key_get('spam-config', 'learn-enable') && !env.test";

# When to learn ham (score >= threshold)
let "AUTOLEARN_HAM_THRESHOLD" "key_get('spam-config', 'learn-ham-threshold')";

# When to learn spam (score <= threshold)
let "AUTOLEARN_SPAM_THRESHOLD" "key_get('spam-config', 'learn-spam-threshold')";

# Keep difference for spam/ham learns for at least this value
let "AUTOLEARN_SPAM_HAM_BALANCE" "key_get('spam-config', 'learn-balance')";

# If ADD_HEADER_SPAM is enabled, mark as SPAM messages with a score above this threshold
let "SCORE_SPAM_THRESHOLD" "key_get('spam-config', 'threshold-spam')";

# Discard messages with a score above this threshold
let "SCORE_DISCARD_THRESHOLD" "key_get('spam-config', 'threshold-discard')";

# Reject messages with a score above this threshold
let "SCORE_REJECT_THRESHOLD" "key_get('spam-config', 'threshold-reject')";

# Directory name to use for local domain lookups (leave empty for default)
let "DOMAIN_DIRECTORY" "key_get('spam-config', 'directory')";

# Store to use for Bayes tokens and ids (leave empty for default)
let "SPAM_DB" "key_get('spam-config', 'lookup')";
