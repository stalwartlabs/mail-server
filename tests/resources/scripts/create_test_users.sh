#!/bin/bash

cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret domain create example.org
cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account create john 12345 -d "John Doe" -a john@example.org -a john.doe@example.org
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account create jane abcde -d "Jane Doe" -a jane@example.org
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account create bill xyz12 -d "Bill Foobar" -a bill@example.org
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret group create sales -d "Sales Department"
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret group create support -d "Technical Support"
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account add-to-group john sales support
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account remove-from-group john support
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account add-email jane jane.doe@example.org
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret list create everyone everyone@example.org
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret list add-members everyone jane john bill
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret account list
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret import messages --format mbox john _ignore/dovecot-crlf 
#cargo run -p stalwart-cli -- -u https://127.0.0.1:443 -c admin:secret import messages --format maildir john /var/mail/john
