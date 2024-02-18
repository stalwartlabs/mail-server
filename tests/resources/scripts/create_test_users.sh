#!/bin/bash

export URL="https://127.0.0.1:443" CREDENTIALS="admin:secret" 

cargo run -p stalwart-cli -- domain create example.org
cargo run -p stalwart-cli -- account create john 12345 -d "John Doe" -a john@example.org -a john.doe@example.org
cargo run -p stalwart-cli -- account create jane abcde -d "Jane Doe" -a jane@example.org
cargo run -p stalwart-cli -- account create bill xyz12 -d "Bill Foobar" -a bill@example.org
cargo run -p stalwart-cli -- group create sales -d "Sales Department"
cargo run -p stalwart-cli -- group create support -d "Technical Support"
cargo run -p stalwart-cli -- account add-to-group john sales support
cargo run -p stalwart-cli -- account remove-from-group john support
cargo run -p stalwart-cli -- account add-email jane jane.doe@example.org
cargo run -p stalwart-cli -- list create everyone everyone@example.org
cargo run -p stalwart-cli -- list add-members everyone jane john bill
cargo run -p stalwart-cli -- account list
cargo run -p stalwart-cli -- import messages --format mbox john _ignore/dovecot-crlf 
cargo run -p stalwart-cli -- import messages --format maildir john /var/mail/john
