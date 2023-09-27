require ["variables", "include", "vnd.stalwart.expressions", "reject"];

global "score";
set "awl_factor" "0.5";

let "result" "query('sql', 'SELECT score, count FROM awl WHERE sender = ? AND ip = ?', [env.from, env.remote_ip])";

let "awl_score" "result[0]";
let "awl_count" "result[1]";

if eval "awl_count > 0" {
	if eval "!query('sql', 'UPDATE awl SET score = score + ?, count = count + 1 WHERE sender = ? AND ip = ?', [score, env.from, env.remote_ip])" {
		reject "update query failed";
		stop;
	}
	let "score" "score + ((awl_score / awl_count) - score) * awl_factor";
} elsif eval "!query('sql', 'INSERT INTO awl (score, count, sender, ip) VALUES (?, 1, ?, ?)', [score, env.from, env.remote_ip])" {
	reject "insert query failed";
	stop;
}
