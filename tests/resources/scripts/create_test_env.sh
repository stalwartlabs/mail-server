#!/bin/bash

BASE_DIR="/Users/me/Downloads/stalwart-test"
FEATURES="sqlite foundationdb postgres mysql rocks elastic s3 redis"

# Delete previous tests
rm -rf $BASE_DIR

# Create admin user
cargo run -p stalwart --no-default-features --features "$FEATURES" -- --init=$BASE_DIR

printf "[server.http]\npermissive-cors = true\n" >> $BASE_DIR/etc/config.toml
printf "[tracer.stdout]\ntype = 'stdout'\nlevel = 'trace'\nansi = true\nenable = true\n" >> $BASE_DIR/etc/config.toml
sed -i '' 's/secret =/secret = "secret"\n#secret =/g' $BASE_DIR/etc/config.toml
#cargo run -p stalwart --no-default-features --features "$FEATURES" -- --config=$BASE_DIR/etc/config.toml
