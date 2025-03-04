require ["fileinto", "mailbox", "mailboxid", "special-use", "ihave", "imap4flags", "vnd.stalwart.expressions"];

# SpecialUse extension tests
if not specialuse_exists ["inbox", "trash"] {
    error "Special-use mailboxes INBOX or TRASH do not exist (lowercase).";
}

if not anyof(specialuse_exists "Inbox" "inbox",
             specialuse_exists "Deleted Items" "trash") {
    error "Special-use mailboxes INBOX or TRASH do not exist (mixed-case).";
}

if specialuse_exists "dingleberry" {
    error "An invalid special-use exists.";
}

if specialuse_exists "archive" {
    error "A non-existent special-use exists.";
}

# MailboxId tests
if not mailboxidexists "a" {
    error "Inbox not found by mailboxid.";
}

if not mailboxidexists ["a", "b"] {
    error "Inbox and Trash mailboxes not found by mailboxid.";
}

# MailboxExists tests
if not mailboxexists "Inbox" {
    error "Inbox not found by name.";
}

if not mailboxexists ["Drafts", "Sent Items"] {
    error "Drafts and Sent Items not found by name.";
}

# File into new mailboxes using flags
fileinto :create "INBOX /  Folder  ";
fileinto :flags ["$important", "\\Seen"] :create "My/Nested/Mailbox/with/multiple/levels";

# Make sure all mailboxes were created
if not mailboxexists "Inbox/Folder" {
    error "'Inbox/Folder' not found.";
}

if not mailboxexists "My/Nested/Mailbox/with/multiple/levels" {
    error "'My/Nested/Mailbox/with/multiple/levels' not found.";
}

if not mailboxexists "My/Nested/Mailbox/with/multiple" {
    error "'My/Nested/Mailbox/with/multiple' not found.";
}

if not mailboxexists "My/Nested" {
    error "'My/Nested' not found.";
}

if not mailboxexists "My" {
    error "'My' not found.";
}

if eval "llm_prompt('echo-test', 'hello world', 0.5) != 'hello world'" {
    error "llm_prompt is unavailable.";
}
