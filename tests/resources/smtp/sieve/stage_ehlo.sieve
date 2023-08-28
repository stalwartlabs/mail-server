require ["variables", "extlists", "reject"];

if string :list "${env.helo_domain}" "local/invalid-ehlos" {
    reject "551 5.1.1 Your domain '${env.helo_domain}' has been blacklisted.";
}
