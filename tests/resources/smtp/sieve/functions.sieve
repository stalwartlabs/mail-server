require ["variables", "include", "vnd.stalwart.plugins", "reject"];

set "address1" "john@doe.example.org";
set "address2" "jane@smith.example.org";
set "address3" "john@example.org";
set "address4" "jane@example.org";
set "address5" "john@localhost";
set "address6" "jane@localhost";

if not string :is "${address1.base_domain()}" "${address2.base_domain()}" {
    reject "${address1.base_domain()} != ${address2.base_domain()}";
    stop;
}

if not string :is "${address3.base_domain()}" "${address4.base_domain()}" {
    reject "${address3.base_domain()} != ${address4.base_domain()}";
    stop;
}

if not string :is "${address5.base_domain()}" "${address6.base_domain()}" {
    reject "${address5.base_domain()} != ${address6.base_domain()}";
    stop;
}

