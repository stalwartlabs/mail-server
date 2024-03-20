# Whether to add an X-Spam-Status header
let "ADD_HEADER_SPAM" "%{cfg:spam.header.add-spam}%";

# Whether to add an X-Spam-Result header
let "ADD_HEADER_SPAM_RESULT" "%{cfg:spam.header.add-spam-result}%";

# Whether message replies from authenticated users should be learned as ham
let "AUTOLEARN_REPLIES_HAM" "%{cfg:spam.autolearn.ham.replies}%";

# Whether the bayes classifier should be trained automatically
let "AUTOLEARN_ENABLE" "%{cfg:spam.autolearn.enable}%";

# When to learn ham (score >= threshold)
let "AUTOLEARN_HAM_THRESHOLD" "%{cfg:spam.autolearn.ham.threshold}%";

# When to learn spam (score <= threshold)
let "AUTOLEARN_SPAM_THRESHOLD" "%{cfg:spam.autolearn.spam.threshold}%";

# Keep difference for spam/ham learns for at least this value
let "AUTOLEARN_SPAM_HAM_BALANCE" "%{cfg:spam.autolearn.balance}%";

# If ADD_HEADER_SPAM is enabled, mark as SPAM messages with a score above this threshold
let "SCORE_SPAM_THRESHOLD" "%{cfg:spam.threshold.spam}%";

# Discard messages with a score above this threshold
let "SCORE_DISCARD_THRESHOLD" "%{cfg:spam.threshold.discard}%";

# Reject messages with a score above this threshold
let "SCORE_REJECT_THRESHOLD" "%{cfg:spam.threshold.reject}%";

# Directory name to use for local domain lookups (leave empty for default)
let "DOMAIN_DIRECTORY" "%{cfg:spam.data.directory}%";

# Store to use for Bayes tokens and ids (leave empty for default)
let "SPAM_DB" "%{cfg:spam.data.lookup}%";
