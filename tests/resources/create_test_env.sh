#!/bin/bash

BASE_DIR="/tmp/stalwart-test"
DOMAIN="example.org"

# Delete previous tests
rm -rf $BASE_DIR

# Create directories
mkdir -p $BASE_DIR $BASE_DIR/data $BASE_DIR/data/blobs $BASE_DIR/logs $BASE_DIR/reports $BASE_DIR/queue

# Copy config files
cp -r resources/config $BASE_DIR/etc

# Copy self-signed certs
cp -r tests/resources/tls_cert.pem $BASE_DIR/etc
cp -r tests/resources/tls_privatekey.pem $BASE_DIR/etc

# Replace settings
sed -i '' -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__HOST__/mail.$DOMAIN/g" -e 's/sql.toml/memory.toml/g' -e "s|__BASE_PATH__|$BASE_DIR|g" "$BASE_DIR/etc/config.toml"
sed -i '' -e "s|__CERT_PATH__|$BASE_DIR/etc/tls_cert.pem|g" -e "s|__PK_PATH__|$BASE_DIR/etc/tls_privatekey.pem|g" "$BASE_DIR/etc/common/tls.toml"
sed -i '' -e 's/method = "log"/method = "stdout"/g' -e 's/level = "info"/level = "trace"/g' "$BASE_DIR/etc/common/tracing.toml"
sed -i '' -e 's/user = "stalwart-mail"//g' -e 's/group = "stalwart-mail"//g' "$BASE_DIR/etc/common/server.toml"

# Generate DKIM key
mkdir -p $BASE_DIR/etc/dkim
openssl genpkey -algorithm RSA -out $BASE_DIR/etc/dkim/$DOMAIN.key

# Create antispam tables
sqlite3 $BASE_DIR/data/spamfilter.sqlite3 <<EOF
CREATE TABLE IF NOT EXISTS bayes_tokens (
h1 INTEGER NOT NULL,
h2 INTEGER NOT NULL,
ws INTEGER,
wh INTEGER,
PRIMARY KEY (h1, h2)
);

CREATE TABLE IF NOT EXISTS seen_ids (
    id STRING NOT NULL PRIMARY KEY,
    ttl DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation (
token STRING NOT NULL PRIMARY KEY,
score FLOAT NOT NULL DEFAULT '0',
count INT(11) NOT NULL DEFAULT '0',
ttl DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
EOF

#cargo run --manifest-path=crates/main/Cargo.toml -- --config=/tmp/stalwart-test/etc/config.toml
