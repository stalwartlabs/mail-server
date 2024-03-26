require ["variables", "extlists", "reject"];

if eval "contains(['spammer.org', 'spammer.net'], env.helo_domain)" {
    reject "551 5.1.1 Your domain '${env.helo_domain}' has been blocklisted.";
}
