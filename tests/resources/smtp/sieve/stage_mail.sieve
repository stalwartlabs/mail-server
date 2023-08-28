require ["variables", "vnd.stalwart.plugins", "envelope", "reject"];

if envelope :localpart :is "from" "spammer" {
    reject "450 4.1.1 Invalid address";
}

query :use "sql" "CREATE TABLE IF NOT EXISTS blocked_senders (addr TEXT PRIMARY KEY)" [];
query :use "sql" "INSERT OR IGNORE INTO blocked_senders (addr) VALUES (?)" "marketing@spam-domain.com";

if query :use "sql" "SELECT 1 FROM blocked_senders WHERE addr=? LIMIT 1" ["${envelope.from}"] {
    reject "Your address has been blocked.";
}
