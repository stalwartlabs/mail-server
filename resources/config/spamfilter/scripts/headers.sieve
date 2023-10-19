# Mailing list scores
let "ml_score" "count(header.List-Id:List-Archive:List-Owner:List-Help:List-Post:X-Loop:List-Subscribe:List-Unsubscribe[*].exists) * 0.125";
if eval "ml_score < 1" {
    if eval "header.List-Id.exists" {
        let "ml_score" "ml_score + 0.50";
    }
    if eval "header.List-Subscribe.exists && header.List-Unsubscribe.exists" {
        let "ml_score" "ml_score + 0.25";
    }
    if eval "header.Precedence.exists && (eq_ignore_case(header.Precedence, 'list') || eq_ignore_case(header.Precedence, 'bulk'))" {
        let "ml_score" "ml_score + 0.25";
    }
}
if eval "ml_score >= 1" {
    let "t.MAILLIST" "1";
}

# X-Priority
if eval "header.x-priority.exists" {
    let "xp" "header.x-priority";
    if eval "xp == 0" {
        let "t.HAS_X_PRIO_ZERO" "1";
    } elsif eval "xp == 1" {
        let "t.HAS_X_PRIO_ONE" "1";
    } elsif eval "xp == 2" {
        let "t.HAS_X_PRIO_TWO" "1";
    } elsif eval "xp <= 4" {
        let "t.HAS_X_PRIO_THREE" "1";
    } elsif eval "xp >= 5" {
        let "t.HAS_X_PRIO_FIVE" "1";
    }
}

let "unique_header_names" "to_lowercase(header.Content-Type:Content-Transfer-Encoding:Date:From:Sender:Reply-To:To:Cc:Bcc:Message-ID:In-Reply-To:References:Subject[*].raw_name)";
if eval "count(unique_header_names) != count(dedup(unique_header_names))" {
    let "t.MULTIPLE_UNIQUE_HEADERS" "1";
}

# Wrong case X-Mailer
if eval "header.x-mailer.exists && header.x-mailer.raw_name != 'X-Mailer'" {
    let "t.XM_CASE" "1";
}

# Has organization header
if eval "header.organization:organisation.exists" {
    let "t.HAS_ORG_HEADER" "1";
}

# Has X-Originating-IP header
if eval "header.X-Originating-IP.exists" {
    let "t.HAS_XOIP" "1";
}

# Has List-Unsubscribe header
if eval "header.List-Unsubscribe.exists" {
    let "t.HAS_LIST_UNSUB" "1";
}

# Missing version number in X-Mailer or User-Agent headers
if eval "(header.X-Mailer.exists && !has_digits(header.X-Mailer)) || (header.User-Agent.exists && !has_digits(header.User-Agent))" {
    let "t.XM_UA_NO_VERSION" "1";
}

# Precedence is bulk
if eval "eq_ignore_case(header.Precedence, 'bulk')" {
    let "t.PRECEDENCE_BULK" "1";
}

# Upstream SPAM filtering
if eval "contains_ignore_case(header.X-KLMS-AntiSpam-Status, 'spam')" {
    # Kaspersky Security for Mail Server says this message is spam
    let "t.KLMS_SPAM" "1";
}
let "spam_hdr" "to_lowercase(header.X-Spam:X-Spam-Flag:X-Spam-Status)";
if eval "contains(spam_hdr, 'yes') || contains(spam_hdr, 'true') || contains(spam_hdr, 'spam')" {
    # Message was already marked as spam
    let "t.SPAM_FLAG" "1";
}
if eval "contains_ignore_case(header.X-UI-Filterresults:X-UI-Out-Filterresults, 'junk')" {
    # United Internet says this message is spam
    let "t.UNITEDINTERNET_SPAM" "1";
}

# Compromised hosts
if eval "header.X-PHP-Originating-Script.exists" {
    let "t.HAS_X_POS" "1";
    if eval "contains(header.X-PHP-Originating-Script, 'eval()')" {
        let "t.X_PHP_EVAL" "1";
    }
    if eval "contains(header.X-PHP-Originating-Script, '../')" {
        let "t.HIDDEN_SOURCE_OBJ" "1";
    }
}
if eval "header.X-PHP-Script.exists" {
    let "t.HAS_X_PHP_SCRIPT" "1";
    if eval "contains(header.X-PHP-Script, 'eval()')" {
        let "t.X_PHP_EVAL" "1";
    }
    if eval "contains(header.X-PHP-Script, 'sendmail.php')" {
        let "t.PHP_XPS_PATTERN" "1";
    }
    if eval "contains(header.X-PHP-Script, '../')" {
        let "t.HIDDEN_SOURCE_OBJ" "1";
    }
}
if eval "contains_ignore_case(header.X-Mailer, 'PHPMailer')" {
    let "t.HAS_PHPMAILER_SIG" "1";
}
if eval "header.X-Source:X-Source-Args:X-Source-Dir.exists" {
    let "t.HAS_X_SOURCE" "1";
    if eval "contains(header.X-Source-Args, '../')" {
        let "t.HIDDEN_SOURCE_OBJ" "1";
    }
}
if eval "contains(header.X-Authenticated-Sender, ': ')" {
    let "t.HAS_X_AS" "1";
}
if eval "contains(header.X-Get-Message-Sender-Via, 'authenticated_id:')" {
    let "t.HAS_X_GMSV" "1";
}
if eval "header.X-AntiAbuse.exists" {
    let "t.HAS_X_ANTIABUSE" "1";
}
if eval "header.X-Authentication-Warning.exists" {
    let "t.HAS_XAW" "1";
}

# Check for empty delimiters in raw headers
let "raw_headers" "header.from:to:cc:subject:reply-to:date[*].raw";
let "i" "count(raw_headers)";
while "i > 0" {
    let "i" "i - 1";
    if eval "!starts_with(raw_headers[i], ' ')" {
        let "t.HEADER_EMPTY_DELIMITER" "1";
        break;
    }
}
