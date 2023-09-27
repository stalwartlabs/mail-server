require ["variables", "include", "vnd.stalwart.expressions", "reject"];

global "score";

# Create AWL table
if eval "!query('sql', 'CREATE TABLE awl (score FLOAT, count INT, sender TEXT NOT NULL, ip TEXT NOT NULL, PRIMARY KEY (sender, ip))' , [])" {
    reject "create table query failed";
    stop;
}


set "score" "1.1";
include "awl_include";
if eval "score != 1.1" {
    reject "awl_include #1 set score to ${score}";
    stop;
}

set "score" "2.2";
include "awl_include";
if eval "score != 1.6500000000000001" {
    reject "awl_include #2 set score to ${score}";
    stop;
}

set "score" "9.3";
include "awl_include";
if eval "score != 5.4750000000000005" {
    reject "awl_include #3 set score to ${score}";
    stop;
}

