require ["variables", "vnd.stalwart.plugins", "envelope", "reject"];

if envelope :domain :is "to" "foobar.org" {
    query :use "sql" "CREATE TABLE IF NOT EXISTS greylist (addr TEXT PRIMARY KEY)" [];

    set "triplet" "${env.remote_ip}.${envelope.from}.${envelope.to}";

    if not query :use "sql" "SELECT 1 FROM greylist WHERE addr=? LIMIT 1" ["${triplet}"] {
        query :use "sql" "INSERT INTO greylist (addr) VALUES (?)" ["${triplet}"];
        reject "422 4.2.2 You have been greylisted '${triplet}'.";
    }
}
