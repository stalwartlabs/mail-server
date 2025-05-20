#!/bin/bash

BASE_DIR="/Users/me/Downloads/stalwart-cluster"
FEATURES="rocks"
NUM_NODES=5

# Kill previous processes
sudo pkill stalwart

# Delete previous tests
rm -rf $BASE_DIR

# Build the stalwart binary
cargo build -p stalwart --no-default-features --features "$FEATURES" 

for NUM in $(seq 1 $NUM_NODES); do
    sudo ifconfig en0 alias 10.0.$NUM.1 netmask 255.255.255.0
    mkdir -p $BASE_DIR/data$NUM
    cat <<EOF | sed "s|_N_|$NUM|g" | sed "s|_D_|$BASE_DIR|g" > $BASE_DIR/config$NUM.toml
cluster.bind-addr = "10.0._N_.1"
cluster.key = "the cluster key"
cluster.seed-nodes = ["10.0.1.1", "10.0.2.1", "10.0.3.1"]
authentication.fallback-admin.secret = "secret"
authentication.fallback-admin.user = "admin"
directory.internal.store = "rocksdb"
directory.internal.type = "internal"
lookup.default.hostname = "mail_N_.example.org"
server.http.permissive-cors = true
server.listener.https.bind = "10.0._N_.1:1443"
server.listener.https.protocol = "http"
server.listener.https.tls.implicit = true
server.listener.imap.bind = "10.0._N_.1:1143"
server.listener.imap.protocol = "imap"
server.listener.smtp.bind = "10.0._N_.1:1125"
server.listener.smtp.protocol = "smtp"
storage.blob = "rocksdb"
storage.data = "rocksdb"
storage.directory = "internal"
storage.fts = "rocksdb"
storage.lookup = "rocksdb"
store.rocksdb.compression = "lz4"
store.rocksdb.path = "_D_/data_N_"
store.rocksdb.type = "rocksdb"
tracer.stdout.ansi = true
tracer.stdout.enable = true
tracer.stdout.level = "debug"
tracer.stdout.type = "stdout"
config.resource.spam-filter = "file:///dev/null"
config.resource.webadmin = "file:///dev/null"
EOF

    sudo ./target/debug/stalwart --config $BASE_DIR/config$NUM.toml &
done
