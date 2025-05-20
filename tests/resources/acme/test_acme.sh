#!/bin/sh

rm -Rf /tmp/stalwart-temp-data
mkdir -p /tmp/stalwart-temp-data
cp ./tests/resources/acme/config.toml /tmp/stalwart-temp-data/config.toml

curl --request POST --data '{"ip":"192.168.5.2"}' http://localhost:8055/set-default-ipv4

cargo run -p stalwart --no-default-features --features "sqlite foundationdb postgres mysql rocks elastic s3 redis" -- --config=/tmp/stalwart-temp-data/config.toml
