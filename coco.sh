#!/bin/bash
while true; do
    cargo test store_test -- --nocapture
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        break
    fi
done
