import os

# Define the scripts and their component files
scripts = {
    "spam-filter": [
               "config.sieve",
               "prelude.sieve",
               "from.sieve",
               "recipient.sieve",
               "subject.sieve",
               "replyto.sieve",
               "date.sieve",
               "messageid.sieve",
               "received.sieve",
               "headers.sieve",
               "bounce.sieve",
               "html.sieve",
               "mime.sieve",
               "dmarc.sieve",
               "ip.sieve",
               "helo.sieve",
               "replies_in.sieve",
               "spamtrap.sieve",
               "bayes_classify.sieve",
               "url.sieve",
               "rbl.sieve",
               "pyzor.sieve",
               "composites.sieve",
               "scores.sieve",
               "reputation.sieve",
               "epilogue.sieve"
    ],
    "track-replies": [
                "config.sieve",
                "replies_out.sieve"
    ],
    "greylist": [
                "config.sieve",
                "greylist.sieve"
    ],
    "train": [
                "config.sieve",
                "train.sieve"
    ]
}
script_names = {
    "spam-filter" : "Spam Filter",
    "track-replies" : "Track Replies",
    "greylist" : "Greylisting",
    "train": "Train Bayes Classifier"
}

maps = ["spam_config.map",
        "scores.map", 
        "allow_dmarc.list", 
        "allow_domains.list", 
        "allow_spf_dkim.list", 
        "domains_disposable.list", 
        "domains_free.list", 
        "mime_types.map", 
        "url_redirectors.list"]


def read_and_concatenate(files):
    content = ""
    for file in files:
        with open(os.path.join("./spamfilter/scripts", file), "r", encoding="utf-8") as f:
            content += "\n#### Script " + file + " ####\n\n"
            content += f.read() + "\n"
    return content

def read_file(file):
    with open(file, "r", encoding="utf-8") as f:
        return f.read() + "\n"

def build_spam_filters(scripts):
    spam_filter = "[version]\nspam-filter = \"1.1\"\n\n"
    for script_name, file_list in scripts.items():
        script_content = read_and_concatenate(file_list).replace("'''", "\\'\\'\\'")
        script_description = script_names[script_name]
        spam_filter += f"[sieve.trusted.scripts.{script_name}]\nname = \"{script_description}\"\ncontents = '''\n{script_content}'''\n\n"

    spam_filter += "\n[lookup]\n"
    for map in maps :
        with open(os.path.join("./spamfilter/maps", map), "r", encoding="utf-8") as f:
            spam_filter += f.read() + "\n"

    return spam_filter

def main():
    spam_filter = build_spam_filters(scripts)
    with open("spamfilter.toml", "w", encoding="utf-8") as toml_file:
        toml_file.write(spam_filter)
    print("Stalwart TOML configuration files have been generated.")

if __name__ == "__main__":
    main()
