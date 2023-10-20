#!/bin/sh

BASE_DIR = "/tmp/stalwart-test"

# Delete previous tests
rm -rf $BASE_DIR

# Create directories
mkdir -p $BASE_DIR $BASE_DIR/data $BASE_DIR/data/blobs $BASE_DIR/logs $BASE_DIR/reports $BASE_DIR/queue

# Copy config files
cp -r resources/config $BASE_DIR/etc

# Copy self-signed certs
cp -r tests/resources/tls_cert.pem $BASE_DIR/etc
cp -r tests/resources/tls_privatekey.pem $BASE_DIR/etc

