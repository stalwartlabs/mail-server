#!/bin/bash

BASE_DIR="/Users/me/Downloads/stalwart-test"
DOMAIN="example.org"
FEATURES="sqlite foundationdb postgres mysql rocks elastic s3 redis"

# Delete previous tests
rm -rf $BASE_DIR

# Create directories
mkdir -p $BASE_DIR $BASE_DIR/data $BASE_DIR/etc

# Copy resources
cp -r resources/config/config.toml $BASE_DIR/etc

# Replace settings

sed -i '' -e "s|%{env:STALWART_PATH}%|$BASE_DIR|g" \
          -e "s|%{env:DOMAIN}%|$DOMAIN|g" \
          -e "s|%{env:HOSTNAME}%|mail.$DOMAIN|g" \
          -e "s|%{env:OAUTH_KEY}%|12345|g" \
          -e 's/level = "info"/level = "trace"/g' "$BASE_DIR/etc/config.toml"

#sed -i '' -e 's/allow-plain-text = false/allow-plain-text = true/g' \
#          -e 's/2000\/1m/9999999\/100m/g' \
#          -e 's/concurrent = 4/concurrent = 90000/g' "$BASE_DIR/etc/imap/settings.toml"

# Create admin user
SET_ADMIN_USER="admin" SET_ADMIN_PASS="secret" cargo run -p mail-server --no-default-features --features "$FEATURES" -- --config=$BASE_DIR/etc/config.toml
cargo run -p mail-server --no-default-features --features "$FEATURES" -- --config=$BASE_DIR/etc/config.toml
