require ["variables", "reject"];

if string "${env.remote_ip}" "10.0.0.88" {
    reject "Your IP '${env.remote_ip}' is not welcomed here.";
}
