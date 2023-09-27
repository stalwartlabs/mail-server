require ["variables", "envelope", "reject", "vnd.stalwart.expressions"];

if envelope :domain :is "to" "foobar.org" {
    eval "query('sql', 'CREATE TABLE IF NOT EXISTS greylist (addr TEXT PRIMARY KEY)', [])";

    set "triplet" "${env.remote_ip}.${envelope.from}.${envelope.to}";

    if eval "!query('sql', 'SELECT 1 FROM greylist WHERE addr=? LIMIT 1', [triplet])" {
        eval "query('sql', 'INSERT INTO greylist (addr) VALUES (?)', [triplet])";
        reject "422 4.2.2 You have been greylisted '${triplet}'.";
    }
}
