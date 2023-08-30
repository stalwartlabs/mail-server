require ["envelope", "reject", "variables", "replace", "mime", "foreverypart", "editheader", "extracttext", "enotify"];

if envelope :localpart :is "to" "thomas" {
    deleteheader "from";
    addheader "From" "no-reply@my.domain";
    redirect "redirect@here.email";
    discard;
}

if envelope :localpart :is "to" "bob" {
    redirect "redirect@somewhere.email";
    discard;
}

if envelope :localpart :is "to" "bill" {
    reject "Bill cannot receive messages.";
    stop;
}

if envelope :localpart :is "to" "jane" {
    set "counter" "a";
    foreverypart {
        if header :mime :contenttype "content-type" "text/html" {
            extracttext :upper "text_content";
            replace "${text_content}";
        }
        set :length "part_num" "${counter}";
        addheader :last "X-Part-Number" "${part_num}";
        set "counter" "${counter}a";
    }
}

if envelope :domain :is "to" "foobar.net" {
    notify "mailto:john@example.net?cc=jane@example.org&subject=You%20have%20got%20mail";
}
