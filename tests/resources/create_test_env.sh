#!/bin/bash

BASE_DIR="/tmp/stalwart-test"
DOMAIN="example.org"

# Stores
STORE="rocksdb"
FTS_STORE="rocksdb"
BLOB_STORE="rocksdb"

# Directories
DIRECTORY="internal"
SQL_STORE="sqlite"

# Delete previous tests
rm -rf $BASE_DIR

# Create directories
mkdir -p $BASE_DIR $BASE_DIR/data $BASE_DIR/data/blobs $BASE_DIR/logs $BASE_DIR/reports $BASE_DIR/queue

# Copy config files
cp -r resources/config $BASE_DIR/etc

# Copy self-signed certs
cp -r tests/resources/tls_cert.pem $BASE_DIR/etc
cp -r tests/resources/tls_privatekey.pem $BASE_DIR/etc

# Replace stores and directories
sed -i '' -e "s|__SQL_STORE__|$SQL_STORE|g" "$BASE_DIR/etc/directory/sql.toml"
sed -i '' -e 's/disable = true//g' "$BASE_DIR/etc/directory/$DIRECTORY.toml"
sed -i '' -e 's/disable = true//g' "$BASE_DIR/etc/store/$STORE.toml"
sed -i '' -e 's/disable = true//g' "$BASE_DIR/etc/store/$FTS_STORE.toml"
sed -i '' -e 's/disable = true//g' "$BASE_DIR/etc/store/$BLOB_STORE.toml"
sed -i '' -e "s/__FTS_STORE__/$FTS_STORE/g" \
          -e "s/__BLOB_STORE__/$BLOB_STORE/g" "$BASE_DIR/etc/jmap/store.toml"

# Replace settings
sed -i ''  -e "s/__STORE__/$STORE/g" \
          -e "s/__DIRECTORY__/$DIRECTORY/g" \
          -e "s/__DOMAIN__/$DOMAIN/g" \
          -e "s/__HOST__/mail.$DOMAIN/g" \
          -e "s|__BASE_PATH__|$BASE_DIR|g" "$BASE_DIR/etc/config.toml"
sed -i '' -e "s|__CERT_PATH__|$BASE_DIR/etc/tls_cert.pem|g" \
          -e "s|__PK_PATH__|$BASE_DIR/etc/tls_privatekey.pem|g" "$BASE_DIR/etc/common/tls.toml"
sed -i '' -e 's/method = "log"/method = "stdout"/g' \
          -e 's/level = "info"/level = "trace"/g' "$BASE_DIR/etc/common/tracing.toml"
sed -i '' -e 's/%{HOST}%/127.0.0.1/g' "$BASE_DIR/etc/jmap/listener.toml"
sed -i '' -e 's/allow-plain-text = false/allow-plain-text = true/g' "$BASE_DIR/etc/imap/settings.toml"
sed -i '' -e 's/user = "stalwart-mail"//g' \
          -e 's/group = "stalwart-mail"//g' "$BASE_DIR/etc/common/server.toml"

# Generate DKIM key
mkdir -p $BASE_DIR/etc/dkim
openssl genpkey -algorithm RSA -out $BASE_DIR/etc/dkim/$DOMAIN.key

: '
SET_ADMIN_USER="admin" SET_ADMIN_PASS="secret" cargo run --manifest-path=crates/main/Cargo.toml -- --config=/tmp/stalwart-test/etc/config.toml
cargo run --manifest-path=crates/main/Cargo.toml -- --config=/tmp/stalwart-test/etc/config.toml
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret domain create example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account create john 12345 -d "John Doe" -a john@example.org -a john.doe@example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account create jane abcde -d "Jane Doe" -a jane@example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account create bill xyz12 -d "Bill Foobar" -a bill@example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret group create sales -d "Sales Department"
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret group create support -d "Technical Support"
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account add-to-group john sales support
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account remove-from-group john support
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account add-email jane jane.doe@example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret list create everyone everyone@example.org
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret list add-members everyone jane john bill
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret account list
cargo run --manifest-path=crates/cli/Cargo.toml -- -u https://127.0.0.1:8080 -c admin:secret import messages --format mbox john _ignore/dovecot-crlf 
'
