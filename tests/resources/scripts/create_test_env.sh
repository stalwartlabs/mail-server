#!/bin/bash

BASE_DIR="/Users/me/Downloads/stalwart-test"
FEATURES="sqlite foundationdb postgres mysql rocks elastic s3 redis"

# Delete previous tests
rm -rf $BASE_DIR

# Create admin user
cargo run -p mail-server --no-default-features --features "$FEATURES" -- --init=$BASE_DIR

echo "[server.http]\npermissive-cors = true\n" >> $BASE_DIR/etc/config.toml
echo "[tracer.stdout]\ntype = 'stdout'\nlevel = 'info'\nansi = true\nenable = true" >> $BASE_DIR/etc/config.toml
#cargo run -p mail-server --no-default-features --features "$FEATURES" -- --config=$BASE_DIR/etc/config.toml
