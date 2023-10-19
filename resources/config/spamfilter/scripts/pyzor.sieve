# Check message hash against Pyzor on public.pyzor.org:24441 using a 5 second timeout
let "pyzor_response" "pyzor_check('public.pyzor.org:24441', 5)";

if eval "!is_empty(pyzor_response) && pyzor_response[0] == 200" {
    let "count" "pyzor_response[1]";
    let "wl_count" "pyzor_response[2]";

    if eval "count > 5 && (wl_count < 10 || wl_count / count < 0.2)" {
        let "t.PYZOR" "1";
    }
}
