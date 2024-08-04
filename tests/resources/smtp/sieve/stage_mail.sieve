require ["variables", "envelope", "reject", "vnd.stalwart.expressions"];

if envelope :localpart :is "from" "spammer" {
    reject "450 4.1.1 Invalid address";
}

eval "query('sql', 'CREATE TABLE IF NOT EXISTS blocked_senders (addr TEXT PRIMARY KEY)', [])";
eval "query('sql', 'INSERT OR IGNORE INTO blocked_senders (addr) VALUES (?)', 'marketing@spam-domain.com')";

if eval "query('sql', 'SELECT 1 FROM blocked_senders WHERE addr=? LIMIT 1', [envelope.from])" {
    reject "Your address has been blocked.";
}

if eval "!is_local_domain('', 'localdomain.org') || is_local_domain('', 'other.org')" {
    let "reason" "'result: ' + is_local_domain('', 'localdomain.org') + ' ' + is_local_domain('', 'other.org')";
    reject "is_local_domain function failed: ${reason}";
}
