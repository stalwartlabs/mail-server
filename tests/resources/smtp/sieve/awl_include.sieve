require ["variables", "include", "vnd.stalwart.plugins", "reject"];

global "score";
set "awl_factor" "0.5";

query :use "sql" :set ["awl_score", "awl_count"] "SELECT score, count FROM awl WHERE sender = ? AND ip = ?" ["${env.from}", "%{env.remote_ip}"];
if eval "awl_count > 0" {
	if not query :use "sql" "UPDATE awl SET score = score + ?, count = count + 1 WHERE sender = ? AND ip = ?" ["%{score}", "${env.from}", "%{env.remote_ip}"] {
		reject "update query failed";
		stop;
	}
	set "score" "%{score + ((awl_score / awl_count) - score) * awl_factor}";
} else {
	if not query :use "sql" "INSERT INTO awl (score, count, sender, ip) VALUES (?, 1, ?, ?)" ["%{score}", "${env.from}", "%{env.remote_ip}"] {
		reject "insert query failed";
		stop;
	}
}
