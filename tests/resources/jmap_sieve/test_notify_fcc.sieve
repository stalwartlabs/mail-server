require ["enotify", "fcc", "mailbox", "editheader", "imap4flags"];

if header :matches "Subject" "*TPS*" {
    notify :message "It's time to file your TPS report."
        :fcc "Notifications" :create
        "mailto:sms_gateway@remote.org?subject=It's%20TPS-o-clock";

    deleteheader "Subject";
    addheader "Subject" "${1}**censored**${2}";
    setflag "$seen";
}

keep;
