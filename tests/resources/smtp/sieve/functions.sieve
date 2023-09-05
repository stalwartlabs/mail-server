require ["variables", "include", "vnd.stalwart.plugins", "reject"];

set "address1" "john@doe.example.org";
set "address2" "jane@smith.example.org";
set "address3" "john@example.org";
set "address4" "jane@example.org";
set "address5" "john@localhost";
set "address6" "jane@localhost";

if not string :is "${address1.subdomain_part()}" "${address2.subdomain_part()}" {
    reject "${address1.subdomain_part()} != ${address2.subdomain_part()}";
    stop;
}

if not string :is "${address3.subdomain_part()}" "${address4.subdomain_part()}" {
    reject "${address3.subdomain_part()} != ${address4.subdomain_part()}";
    stop;
}

if not string :is "${address5.subdomain_part()}" "${address6.subdomain_part()}" {
    reject "${address5.subdomain_part()} != ${address6.subdomain_part()}";
    stop;
}

