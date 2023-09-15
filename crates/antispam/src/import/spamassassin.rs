use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Display, Write},
    fs::{self},
    path::PathBuf,
    str::FromStr,
};

use super::{
    tokenizer::Tokenizer,
    utils::{fix_broken_regex, import_regex, replace_tags},
    Header, HeaderMatches, HeaderPart, MetaExpression, ReceivedPart, Rule, RuleType, TestFlag,
    Token, UnwrapResult,
};

const VERSION: f64 = 4.000000;

static IF_TRUE: [&str; 53] = [
    "Mail::SpamAssassin::Plugin::DKIM",
    "Mail::SpamAssassin::Plugin::SPF",
    "Mail::SpamAssassin::Plugin::ASN",
    "Mail::SpamAssassin::Plugin::AWL",
    "Mail::SpamAssassin::Plugin::AskDNS",
    "Mail::SpamAssassin::Plugin::AutoLearnThreshold",
    "Mail::SpamAssassin::Plugin::Bayes",
    "Mail::SpamAssassin::Plugin::BodyEval",
    "Mail::SpamAssassin::Plugin::DCC",
    "Mail::SpamAssassin::Plugin::DMARC",
    "Mail::SpamAssassin::Plugin::DNSEval",
    "Mail::SpamAssassin::Plugin::Dmarc",
    "Mail::SpamAssassin::Plugin::FreeMail",
    "Mail::SpamAssassin::Plugin::FromNameSpoof",
    "Mail::SpamAssassin::Plugin::HTMLEval",
    "Mail::SpamAssassin::Plugin::HTTPSMismatch",
    "Mail::SpamAssassin::Plugin::HashBL",
    "Mail::SpamAssassin::Plugin::HeaderEval",
    "Mail::SpamAssassin::Plugin::ImageInfo",
    "Mail::SpamAssassin::Plugin::MIMEEval",
    "Mail::SpamAssassin::Plugin::MIMEHeader",
    "Mail::SpamAssassin::Plugin::PDFInfo",
    "Mail::SpamAssassin::Plugin::Pyzor",
    "Mail::SpamAssassin::Plugin::Razor2",
    "Mail::SpamAssassin::Plugin::RelayEval",
    "Mail::SpamAssassin::Plugin::ReplaceTags",
    "Mail::SpamAssassin::Plugin::TextCat",
    "Mail::SpamAssassin::Plugin::TxRep",
    "Mail::SpamAssassin::Plugin::URIDNSBL",
    "Mail::SpamAssassin::Plugin::URIEval",
    "Mail::SpamAssassin::Plugin::WLBLEval",
    "Mail::SpamAssassin::Plugin::WelcomeListSubject",
    "Mail::SpamAssassin::Conf::feature_bayes_stopwords",
    "Mail::SpamAssassin::Conf::feature_bug6558_free",
    "Mail::SpamAssassin::Conf::feature_capture_rules",
    "Mail::SpamAssassin::Conf::feature_dns_local_ports_permit_avoid",
    "Mail::SpamAssassin::Conf::feature_originating_ip_headers",
    "Mail::SpamAssassin::Conf::feature_registryboundaries",
    "Mail::SpamAssassin::Conf::feature_welcomelist_blocklist",
    "Mail::SpamAssassin::Conf::feature_yesno_takes_args",
    "Mail::SpamAssassin::Conf::perl_min_version_5010000",
    "Mail::SpamAssassin::Plugin::BodyEval::has_check_body_length",
    "Mail::SpamAssassin::Plugin::DKIM::has_arc",
    "Mail::SpamAssassin::Plugin::DecodeShortURLs::has_get",
    "Mail::SpamAssassin::Plugin::DecodeShortURLs::has_short_url_redir",
    "Mail::SpamAssassin::Plugin::MIMEEval::has_check_abundant_unicode_ratio",
    "Mail::SpamAssassin::Plugin::MIMEEval::has_check_for_ascii_text_illegal",
    "Mail::SpamAssassin::Plugin::SPF::has_check_for_spf_errors",
    "Mail::SpamAssassin::Plugin::URIDNSBL::has_tflags_domains_only",
    "Mail::SpamAssassin::Plugin::URIDNSBL::has_uridnsbl_for_a",
    "Mail::SpamAssassin::Plugin::ASN::has_check_asn",
    "Mail::SpamAssassin::Conf::compat_welcomelist_blocklist",
    "Mail::SpamAssassin::Conf::feature_dns_block_rule",
];

static IF_FALSE: [&str; 5] = [
    "Mail::SpamAssassin::Plugin::WhiteListSubject",
    "Mail::SpamAssassin::Plugin::AccessDB",
    "Mail::SpamAssassin::Plugin::AntiVirus",
    "Mail::SpamAssassin::Plugin::Shortcircuit",
    "Mail::SpamAssassin::Plugin::VBounce",
];

static SUPPORTED_FUNCTIONS: [&str; 162] = [
    "check_abundant_unicode_ratio",
    "check_access_database",
    "check_all_trusted",
    "check_arc_signed",
    "check_arc_valid",
    "check_base64_length",
    "check_bayes",
    "check_blank_line_ratio",
    "check_body_8bits",
    "check_body_length",
    "check_dcc",
    "check_dcc_reputation_range",
    "check_dkim_adsp",
    "check_dkim_dependable",
    "check_dkim_signall",
    "check_dkim_signed",
    "check_dkim_signsome",
    "check_dkim_testing",
    "check_dkim_valid",
    "check_dkim_valid_author_sig",
    "check_dkim_valid_envelopefrom",
    "check_dmarc_missing",
    "check_dmarc_none",
    "check_dmarc_pass",
    "check_dmarc_quarantine",
    "check_dmarc_reject",
    "check_dns_sender",
    "check_equal_from_domains",
    "check_for_ascii_text_illegal",
    "check_for_def_dkim_welcomelist_from",
    "check_for_def_dkim_whitelist_from",
    "check_for_def_spf_welcomelist_from",
    "check_for_def_spf_whitelist_from",
    "check_for_dkim_welcomelist_from",
    "check_for_dkim_whitelist_from",
    "check_for_fake_aol_relay_in_rcvd",
    "check_for_faraway_charset",
    "check_for_faraway_charset_in_headers",
    "check_for_forged_eudoramail_received_headers",
    "check_for_forged_gmail_received_headers",
    "check_for_forged_hotmail_received_headers",
    "check_for_forged_juno_received_headers",
    "check_for_forged_received_trail",
    "check_for_forged_yahoo_received_headers",
    "check_for_matching_env_and_hdr_from",
    "check_for_mime",
    "check_for_mime_html",
    "check_for_mime_html_only",
    "check_for_missing_to_header",
    "check_for_no_hotmail_received_headers",
    "check_for_no_rdns_dotcom_helo",
    "check_for_shifted_date",
    "check_for_spf_fail",
    "check_for_spf_helo_fail",
    "check_for_spf_helo_neutral",
    "check_for_spf_helo_none",
    "check_for_spf_helo_pass",
    "check_for_spf_helo_permerror",
    "check_for_spf_helo_softfail",
    "check_for_spf_helo_temperror",
    "check_for_spf_neutral",
    "check_for_spf_none",
    "check_for_spf_pass",
    "check_for_spf_permerror",
    "check_for_spf_softfail",
    "check_for_spf_temperror",
    "check_for_spf_welcomelist_from",
    "check_for_spf_whitelist_from",
    "check_for_to_in_subject",
    "check_for_uppercase",
    "check_freemail_from",
    "check_freemail_header",
    "check_freemail_replyto",
    "check_from_in_auto_welcomelist",
    "check_from_in_auto_whitelist",
    "check_from_in_blacklist",
    "check_from_in_blocklist",
    "check_from_in_default_welcomelist",
    "check_from_in_default_whitelist",
    "check_from_in_list",
    "check_from_in_welcomelist",
    "check_from_in_whitelist",
    "check_fromname_equals_replyto",
    "check_fromname_equals_to",
    "check_fromname_spoof",
    "check_hashbl_bodyre",
    "check_header_count_range",
    "check_https_http_mismatch",
    "check_https_ip_mismatch",
    "check_iframe_src",
    "check_illegal_chars",
    "check_language",
    "check_ma_non_text",
    "check_mailfrom_matches_rcvd",
    "check_microsoft_executable",
    "check_mime_multipart_ratio",
    "check_msg_parse_flags",
    "check_no_relays",
    "check_outlook_message_id",
    "check_pyzor",
    "check_ratware_envelope_from",
    "check_ratware_name_id",
    "check_razor2",
    "check_razor2_range",
    "check_rbl",
    "check_rbl_sub",
    "check_rbl_txt",
    "check_relays_unparseable",
    "check_replyto_in_list",
    "check_senders_reputation",
    "check_shortcircuit",
    "check_stock_info",
    "check_subject_in_blacklist",
    "check_subject_in_blocklist",
    "check_subject_in_welcomelist",
    "check_subject_in_whitelist",
    "check_suspect_name",
    "check_to_in_all_spam",
    "check_to_in_blacklist",
    "check_to_in_blocklist",
    "check_to_in_more_spam",
    "check_to_in_welcomelist",
    "check_to_in_whitelist",
    "check_unresolved_template",
    "check_uri_host_in_blacklist",
    "check_uri_host_in_blocklist",
    "check_uri_host_in_welcomelist",
    "check_uri_host_in_whitelist",
    "check_uri_host_listed",
    "check_uri_truncated",
    "check_uridnsbl",
    "check_welcomelist_bounce_relays",
    "check_whitelist_bounce_relays",
    "gated_through_received_hdr_remover",
    "have_any_bounce_relays",
    "helo_ip_mismatch",
    "html_charset_faraway",
    "html_eval",
    "html_image_only",
    "html_image_ratio",
    "html_range",
    "html_tag_balance",
    "html_tag_exists",
    "html_test",
    "html_text_match",
    "html_title_subject_ratio",
    "image_count",
    "image_to_text_ratio",
    "multipart_alternative_difference",
    "multipart_alternative_difference_count",
    "pdf_image_size_range",
    "pdf_image_to_text_ratio",
    "pdf_is_empty_body",
    "pdf_is_encrypted",
    "pdf_match_details",
    "pixel_coverage",
    "short_url",
    "short_url_chained",
    "similar_recipients",
    "sorted_recipients",
    "subject_is_all_caps",
    "tvd_vertical_words",
];

pub fn import_spamassassin(path: PathBuf, extension: String, do_warn: bool) {
    let mut paths: Vec<_> = fs::read_dir(&path)
        .unwrap_result("read directory")
        .map(|r| r.unwrap_result("read directory entry"))
        .collect();
    paths.sort_by_key(|dir| dir.path());

    let mut rules: HashMap<String, Rule> = HashMap::new();
    let mut lists: HashMap<String, HashSet<String>> = HashMap::new();

    let mut replace_start = '<';
    let mut replace_end = '>';
    let mut replace_rules: HashSet<String> = HashSet::new();
    let mut tags: HashMap<String, String> = HashMap::new();

    let mut unsupported_ifs: BTreeMap<String, HashMap<PathBuf, Vec<String>>> = BTreeMap::new();
    let mut unsupported_commands: BTreeMap<String, HashMap<PathBuf, Vec<String>>> = BTreeMap::new();
    let mut common_headers = BTreeMap::new();

    for path in paths {
        let path = path.path();

        if path
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            != extension
        {
            continue;
        }

        /*if !path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("23_bayes")
        {
            continue;
        }*/

        let mut is_supported_block = true;
        let mut is_supported_stack = Vec::new();

        for (line_num, line_) in fs::read_to_string(&path)
            .unwrap_or_else(|_| {
                let bytes = fs::read(&path).unwrap_result(&format!("read file {}", path.display()));
                if do_warn {
                    eprintln!(
                        "Warning: file {} opened using ISO-8859-1 encoding",
                        path.display()
                    );
                }
                bytes.iter().map(|&c| c as char).collect()
            })
            .lines()
            .enumerate()
        {
            let mut line = String::with_capacity(line_.len());
            let mut last_ch = ' ';
            for ch in line_.chars() {
                if ch.is_ascii_whitespace() {
                    if line.is_empty() {
                        continue;
                    } else {
                        line.push(' ');
                    }
                } else if ch == '#' && last_ch != '\\' {
                    break;
                } else {
                    line.push(ch);
                }
                last_ch = ch;
            }

            let (cmd, mut params) = line
                .split_once(' ')
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or((line.as_str().trim(), ""));

            if cmd.is_empty() {
                continue;
            }

            match cmd {
                "ifplugin" => {
                    is_supported_stack.push(is_supported_block);
                    is_supported_block = IF_TRUE.contains(&params);

                    if !is_supported_block && !IF_FALSE.contains(&params) {
                        unsupported_ifs
                            .entry(params.to_string())
                            .or_default()
                            .entry(path.clone())
                            .or_default()
                            .push(line_num.to_string());
                    }
                }
                "if" => {
                    let _params = params;
                    let mut is_not = false;
                    loop {
                        let mut has_changes = false;
                        if let Some(expr) = params.strip_prefix('!') {
                            is_not = !is_not;
                            params = expr.trim();
                            has_changes = true;
                        }
                        if let Some(expr) =
                            params.strip_prefix('(').and_then(|v| v.strip_suffix(')'))
                        {
                            params = expr.trim();
                            has_changes = true;
                        }
                        if let Some(expr) = params
                            .strip_prefix("can(")
                            .or_else(|| params.strip_prefix("plugin("))
                            .and_then(|v| v.strip_suffix(')'))
                        {
                            params = expr.trim();
                            has_changes = true;
                        }
                        if !has_changes {
                            break;
                        }
                    }

                    if let Some(version) = params.strip_prefix("version ") {
                        is_supported_stack.push(is_supported_block);
                        let (op, version) = version.trim().split_once(' ').unwrap_or(("", version));
                        let version = version
                            .parse::<f64>()
                            .unwrap_result("Failed to parse version");
                        match op {
                            "<" => {
                                is_supported_block = (VERSION < version) ^ is_not;
                            }
                            "<=" => {
                                is_supported_block = (VERSION <= version) ^ is_not;
                            }
                            ">" => {
                                is_supported_block = (VERSION > version) ^ is_not;
                            }
                            ">=" => {
                                is_supported_block = (VERSION >= version) ^ is_not;
                            }
                            "==" => {
                                is_supported_block = (VERSION == version) ^ is_not;
                            }
                            "!=" => {
                                is_supported_block = (VERSION != version) ^ is_not;
                            }
                            _ => {
                                eprintln!(
                                    "Warning: Invalid version operator on {}, line {}",
                                    path.display(),
                                    line_num
                                );
                            }
                        }
                    } else {
                        is_supported_stack.push(is_supported_block);
                        is_supported_block = IF_TRUE.contains(&params);
                        if !is_supported_block && !IF_FALSE.contains(&params) {
                            unsupported_ifs
                                .entry(params.to_string())
                                .or_default()
                                .entry(path.clone())
                                .or_default()
                                .push(line_num.to_string());
                        }
                        is_supported_block ^= is_not;
                    }
                }
                "endif" => {
                    if let Some(last_if) = is_supported_stack.pop() {
                        is_supported_block = last_if;
                    } else {
                        eprintln!(
                            "Warning: Unmatched endif on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                _ if !is_supported_block => {}

                "describe" => {
                    if let Some((name, description)) = params.split_once(' ') {
                        let description = description.trim();
                        if !description.is_empty() {
                            rules
                                .entry(name.to_string())
                                .or_default()
                                .description
                                .insert("en".to_string(), description.to_string());
                        }
                    }
                }

                "header" | "body" | "rawbody" | "full" | "mimeheader" | "uri" => {
                    if let Some((name, value)) =
                        params.split_once(' ').map(|(k, v)| (k.trim(), v.trim()))
                    {
                        let rule = rules.entry(name.to_string()).or_default();

                        if let Some(function) = value.strip_prefix("eval:") {
                            if let Some((fnc_name, params_)) = function
                                .split_once('(')
                                .and_then(|(k, v)| (k.trim(), v.trim().strip_suffix(')')?).into())
                            {
                                if SUPPORTED_FUNCTIONS.contains(&fnc_name) {
                                    let mut params = Vec::new();
                                    let mut in_quote = false;
                                    let mut is_escaped = false;
                                    let mut buf = String::new();

                                    for ch in params_.chars() {
                                        match ch {
                                            '"' | '\'' if !is_escaped => {
                                                buf.push('\"');
                                                if in_quote {
                                                    params.push(buf);
                                                    buf = String::new();
                                                    in_quote = false;
                                                } else {
                                                    in_quote = true;
                                                }
                                            }
                                            ' ' if !in_quote => {}
                                            ',' if !in_quote => {
                                                if !buf.is_empty() {
                                                    params.push(buf);
                                                    buf = String::new();
                                                }
                                            }
                                            _ => {
                                                if is_escaped {
                                                    is_escaped = false;
                                                } else if ch == '\\' {
                                                    is_escaped = true;
                                                }

                                                buf.push(ch);
                                            }
                                        }
                                    }
                                    if !buf.is_empty() {
                                        params.push(buf);
                                    }
                                    rule.t = RuleType::Eval {
                                        function: fnc_name.to_string(),
                                        params,
                                    };
                                } else {
                                    eprintln!(
                                        "Warning: Unsupported function {function:?} on {}, line {}",
                                        path.display(),
                                        line_num
                                    );
                                }
                            } else {
                                eprintln!(
                                    "Warning: Invalid function {function:?} on {}, line {}",
                                    path.display(),
                                    line_num
                                );
                            }
                        } else if cmd == "header" || cmd == "mimeheader" {
                            if let Some(exists) = value.strip_prefix("exists:") {
                                rule.t = RuleType::Header {
                                    matches: HeaderMatches::Exists,
                                    header: Header::Name(exists.to_string()),
                                    pattern: String::new(),
                                    part: HeaderPart::Default,
                                };
                            } else if let Some((header, (op, mut pattern))) = value
                                .split_once(' ')
                                .and_then(|(k, v)| (k.trim(), v.trim().split_once(' ')?).into())
                            {
                                let (header, part) = header.split_once(':').unwrap_or((header, ""));
                                let part = part.split(':').filter_map(|part| {
                                    match part.trim() {
                                        "name" => {Some(HeaderPart::Name)}
                                        "addr" => {Some(HeaderPart::Addr)}
                                        "raw" => {Some(HeaderPart::Raw)}
                                        "" => None,
                                        _ => {
                                            eprintln!(
                                                "Warning: Invalid header part {part:?} on {}, line {}",
                                                path.display(),
                                                line_num
                                            );
                                            None
                                        }
                                    }

                                }).collect::<Vec<_>>();
                                let header = match header {
                                    "ALL" | "ALL-EXTERNAL" => Header::All,
                                    "MESSAGEID" => Header::MessageId,
                                    "EnvelopeFrom" => Header::EnvelopeFrom,
                                    "ToCc" => Header::ToCc,
                                    _ => Header::Name(header.to_lowercase()),
                                };
                                let part = if part.contains(&HeaderPart::Addr) {
                                    HeaderPart::Addr
                                } else if part.contains(&HeaderPart::Name) {
                                    HeaderPart::Name
                                } else if part.contains(&HeaderPart::Raw) {
                                    HeaderPart::Raw
                                } else {
                                    HeaderPart::Default
                                };

                                let mut matches = match op {
                                    "=~" => HeaderMatches::Matches,
                                    "!~" => HeaderMatches::NotMatches,
                                    _ => {
                                        panic!(
                                            "Warning: Invalid operator {op:?} on {}, line {}",
                                            path.display(),
                                            line_num
                                        );
                                    }
                                };

                                if let Some((new_pattern, if_unset)) =
                                    pattern.rsplit_once("[if-unset:")
                                {
                                    pattern = new_pattern.trim();
                                    if let Some(if_unset) =
                                        if_unset.strip_suffix(']').map(|v| v.trim())
                                    {
                                        if pattern == format!("^{if_unset}$") {
                                            // convert /^UNSET$/ [if-unset: UNSET] to exists
                                            pattern = "";
                                            matches = HeaderMatches::NotExists;
                                        }
                                    } else {
                                        panic!(
                                            "Warning: Failed to parse if_unset for header command on {}, line {}",
                                            path.display(),
                                            line_num
                                        );
                                    }
                                }

                                rule.t = RuleType::Header {
                                    matches,
                                    header,
                                    pattern: fix_broken_regex(pattern).to_string(),
                                    part,
                                };
                            } else {
                                eprintln!(
                                    "Warning: Invalid header command on {}, line {}",
                                    path.display(),
                                    line_num
                                );
                            }
                        } else if value.starts_with('/') || value.starts_with('m') {
                            let pattern = fix_broken_regex(value).to_string();
                            rule.t = match cmd {
                                "body" | "rawbody" => RuleType::Body {
                                    pattern,
                                    raw: cmd == "rawbody",
                                },
                                "full" => RuleType::Full { pattern },
                                "uri" => RuleType::Uri { pattern },

                                _ => unreachable!(),
                            }
                        } else {
                            eprintln!(
                                "Warning: Invalid header command on {}, line {}",
                                path.display(),
                                line_num
                            );
                        }
                    } else {
                        eprintln!(
                            "Warning: Invalid header command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "lang" => {
                    if let Some((lang, (command, params))) = params.split_once(' ').map(|(k, v)| {
                        (k.trim(), v.trim().split_once(' ').unwrap_or((v.trim(), "")))
                    }) {
                        if command == "describe" {
                            if let Some((id, description)) = params.trim().split_once(' ') {
                                let description = description.trim();
                                if !description.is_empty() {
                                    rules
                                        .entry(id.to_string())
                                        .or_default()
                                        .description
                                        .insert(lang.to_string(), description.to_string());
                                }
                            } else {
                                eprintln!(
                                    "Warning: Invalid lang command on {}, line {}",
                                    path.display(),
                                    line_num
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "Warning: Invalid lang command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "meta" => {
                    if let Some((test_name, expression)) = params.split_once(' ') {
                        rules.entry(test_name.to_string()).or_default().t = RuleType::Meta {
                            expr: MetaExpression {
                                tokens: Tokenizer::new(expression).collect(),
                                expr: expression.to_string(),
                            },
                        };
                    } else {
                        eprintln!(
                            "Warning: Invalid meta command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }

                "priority" => {
                    let mut params = params.split_ascii_whitespace();
                    if let (Some(id), Some(priority)) = (
                        params.next(),
                        params.next().and_then(|v| v.trim().parse::<i32>().ok()),
                    ) {
                        rules.entry(id.to_string()).or_default().priority = priority;
                    } else {
                        eprintln!(
                            "Warning: Invalid priority command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }

                "score" => {
                    let mut params = params.split_ascii_whitespace();
                    if let Some(id) = params.next() {
                        let mut score_list = Vec::new();
                        for score in params {
                            if let Ok(score) = score.parse::<f64>() {
                                score_list.push(score);
                            } else {
                                eprintln!(
                                    "Warning: Failed to parse score on {}, line {}",
                                    path.display(),
                                    line_num
                                );
                            }
                        }

                        if score_list.len() > 4 {
                            eprintln!(
                                "Warning: Too many scores on {}, line {}",
                                path.display(),
                                line_num
                            );
                        } else if score_list.is_empty() {
                            eprintln!(
                                "Warning: No scores found on {}, line {}",
                                path.display(),
                                line_num
                            );
                        }

                        rules.entry(id.to_string()).or_default().scores = score_list;
                    } else {
                        eprintln!(
                            "Warning: Invalid score command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "tflags" => {
                    let TODO = "implement flags";
                    let mut params = params.split_ascii_whitespace();
                    if let Some(test_name) = params.next() {
                        let test_flags = &mut rules.entry(test_name.to_string()).or_default().flags;
                        for flag in params {
                            test_flags.push(match flag {
                                "net" => {
                                    TestFlag::Net
                                }
                                "nice" => {TestFlag::Nice}
                                "userconf" => {TestFlag::UserConf}
                                "learn" => {TestFlag::Learn}
                                "noautolearn" => {TestFlag::NoAutoLearn}
                                "publish" => {TestFlag::Publish}
                                "multiple" => {TestFlag::Multiple}
                                "notrim" => {TestFlag::NoTrim}
                                "domains_only" => {TestFlag::DomainsOnly}
                                "nosubject" => {TestFlag::NoSubject}
                                "autolearn_body" => {TestFlag::AutoLearnBody}
                                "a" => {TestFlag::A}
                                _ => {
                                    match flag.split_once('=').and_then(|(k, v)| {
                                        (k.trim(), v.trim().parse::<u32>().ok()?).into()
                                    }) {
                                        Some(("maxhits", value)) => {TestFlag::MaxHits(value)}
                                        _ => {
                                            eprintln!(
                                                    "Warning: Invalid tflags value {flag} on {}, line {}",
                                                    path.display(),
                                                    line_num
                                                );
                                                continue;
                                        }
                                    }
                                }
                            });
                        }
                    } else {
                        eprintln!(
                            "Warning: Invalid tflags command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }

                "replace_rules" => {
                    for test_name in params.split_ascii_whitespace() {
                        replace_rules.insert(test_name.to_string());
                    }
                }
                "replace_tag" | "replace_inter" | "replace_post" | "replace_pre" => {
                    if let Some((tag, pattern)) = params.split_once(' ') {
                        let pattern = replace_tags(pattern, replace_start, replace_end, &tags);
                        let tag_class = cmd.strip_prefix("replace_").unwrap();
                        let tag = if tag_class != "tag" {
                            format!("{} {}", tag_class, tag)
                        } else {
                            tag.to_string()
                        };
                        tags.insert(tag, pattern);
                    } else {
                        eprintln!(
                            "Warning: Invalid replace_tag command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "replace_start" => {
                    if let Some(ch) = params.chars().next() {
                        replace_start = ch;
                    }
                }
                "replace_end" => {
                    if let Some(ch) = params.chars().next() {
                        replace_end = ch;
                    }
                }

                "askdns" => {
                    if let Some((test_name, query, (record_type, pattern))) = params
                        .split_once(' ')
                        .and_then(|(a, b)| (a.trim(), b.trim().split_once(' ')?).into())
                        .and_then(|(a, (b, c))| (a, b.trim(), c.trim().split_once(' ')?).into())
                    {
                        rules.entry(test_name.to_string()).or_default().t = RuleType::Eval {
                            function: "askdns".to_string(),
                            params: vec![
                                query.to_string(),
                                record_type.to_string(),
                                pattern.to_string(),
                            ],
                        };
                    } else {
                        eprintln!(
                            "Warning: Invalid askdns command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "def_welcomelist_auth"
                | "def_welcomelist_from_dkim"
                | "def_welcomelist_from_spf" => {
                    let list = lists
                        .entry(
                            cmd.strip_prefix("def_welcomelist_")
                                .unwrap()
                                .replace('_', "-"),
                        )
                        .or_default();
                    for item in params.split_ascii_whitespace() {
                        list.insert(item.to_string());
                    }
                }
                "else" => {
                    is_supported_block = !is_supported_block;
                }
                "enlist_addrlist" | "enlist_uri_host" => {
                    let mut params = params.split_ascii_whitespace();
                    if let Some(list_name) = params
                        .next()
                        .and_then(|s| s.strip_prefix('('))
                        .and_then(|s| s.strip_suffix(')'))
                    {
                        let list = lists
                            .entry(format!(
                                "{}-{}",
                                cmd.strip_prefix("enlist_").unwrap().replace('_', "-"),
                                list_name.to_lowercase()
                            ))
                            .or_default();
                        for item in params {
                            list.insert(item.to_string());
                        }
                    } else {
                        eprintln!(
                            "Warning: Invalid enlist command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "freemail_domains"
                | "uridnsbl_skip_domain"
                | "url_shortener"
                | "url_shortener_get"
                | "util_rb_2tld"
                | "util_rb_3tld"
                | "util_rb_tld"
                | "originating_ip_headers"
                | "redirector_pattern"
                | "bayes_ignore_header" => {
                    let list = lists.entry(cmd.replace('_', "-")).or_default();
                    for item in params.split_ascii_whitespace() {
                        list.insert(item.to_string());
                    }
                }
                "uridnssub" | "urirhssub" => {
                    if let Some((test_name, queryhost, (record_type, result))) = params
                        .split_once(' ')
                        .and_then(|(a, b)| (a.trim(), b.trim().split_once(' ')?).into())
                        .and_then(|(a, (b, c))| (a, b.trim(), c.trim().split_once(' ')?).into())
                    {
                        rules.entry(test_name.to_string()).or_default().t = RuleType::Eval {
                            function: cmd.to_string(),
                            params: vec![
                                queryhost.to_string(),
                                record_type.to_string(),
                                result.to_string(),
                            ],
                        };
                    } else {
                        eprintln!(
                            "Warning: Invalid {cmd} command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }
                "dns_block_rule" => {
                    if let Some((test_name, host)) = params.split_once(' ') {
                        rules
                            .entry(test_name.to_string())
                            .or_default()
                            .flags
                            .push(TestFlag::DnsBlockRule(host.trim().to_string()));
                    } else {
                        eprintln!(
                            "Warning: Invalid {cmd} command on {}, line {}",
                            path.display(),
                            line_num
                        );
                    }
                }

                "ok_languages" => {
                    lists
                        .entry("ok_languages".to_string())
                        .or_default()
                        .extend(params.split_whitespace().map(|v| v.to_string()));
                }

                "fns_check"
                | "fns_ignore_dkim"
                | "fns_ignore_headers"
                | "dns_local_ports_avoid"
                | "def_whitelist_auth"
                | "def_whitelist_from_dkim"
                | "def_whitelist_from_spf"
                | "asn_lookup"
                | "adsp_override"
                | "reuse"
                | "test"
                | "report"
                | "report_contact"
                | "report_safe"
                | "require_version"
                | "required_score"
                | "ok_locales"
                | "unsafe_report"
                | "add_header"
                | "clear_headers"
                | "clear_originating_ip_headers"
                | "clear_report_template"
                | "clear_unsafe_report_template"
                | "clear_util_rb" => {} // Ignored

                _ => {
                    if !cmd.starts_with("bayes_") {
                        unsupported_commands
                            .entry(cmd.to_string())
                            .or_default()
                            .entry(path.clone())
                            .or_default()
                            .push(line_num.to_string());
                    }
                }
            }
        }

        if !is_supported_stack.is_empty() {
            eprintln!("Warning: Unmatched if on {}", path.display(),);
        }
    }

    //println!("description: {:#?}", descriptions);
    //println!("scores: {:#?}", ifs);

    for test_name in replace_rules {
        if let Some(rule) = rules.get_mut(&test_name) {
            match rule.t.pattern() {
                Some(pattern) if !pattern.is_empty() => {
                    *pattern = replace_tags(pattern, replace_start, replace_end, &tags);
                }
                _ => {
                    eprintln!("Warning: Empty pattern for replace_rules command.",);
                }
            }
        } else {
            eprintln!("Warning: Test {test_name:?} not found for replace_rules command.",);
        }
    }

    let mut var_to_rule: HashMap<String, String> = HashMap::new();
    let mut rules = rules
        .into_iter()
        .flat_map(|(name, mut rule)| {
            let mut result = vec![];
            rule.name = name;

            match &mut rule.t {
                RuleType::Header {
                    pattern,
                    header: Header::Name(hdr_name),
                    ..
                } if hdr_name.to_lowercase().starts_with("x-spam-relays-") => {
                    #[derive(Debug)]
                    enum Part {
                        Id(Vec<ReceivedPart>),
                        Pattern(String),
                    }
                    let (pattern_, flags, _) = import_regex(pattern);
                    let mut buf = String::new();
                    let mut parts = vec![];
                    let mut last_ch = char::from(0);

                    for ch in pattern_.chars() {
                        if ch == '=' && (last_ch.is_alphabetic() || last_ch == ')') {
                            let mut found_suffix = false;
                            for (ids, key) in [
                                (vec![ReceivedPart::From], "helo"),
                                (vec![ReceivedPart::Protocol], "auth"),
                                (vec![ReceivedPart::FromIp], "ip"),
                                (vec![ReceivedPart::FromIpRev], "rdns"),
                                (vec![ReceivedPart::For], "envfrom"),
                                (vec![ReceivedPart::By], "by"),
                                (vec![ReceivedPart::Ident], "ident"),
                                (
                                    vec![ReceivedPart::From, ReceivedPart::FromIpRev],
                                    "(?:rdns|helo)",
                                ),
                                (vec![ReceivedPart::Id], "id"),
                                (vec![ReceivedPart::By, ReceivedPart::FromIp], "(?:by|ip)"),
                            ] {
                                if let Some(v) = buf.strip_suffix(key) {
                                    parts.push(Part::Pattern(v.trim().to_string()));
                                    parts.push(Part::Id(ids));
                                    found_suffix = true;
                                    break;
                                }
                            }

                            if !found_suffix {
                                panic!("Failed to parse x-spam-relays- pattern {pattern_}: {buf}");
                            }
                            buf.clear();
                        } else {
                            buf.push(ch);
                        }

                        last_ch = ch;
                    }

                    if !buf.is_empty() {
                        parts.push(Part::Pattern(buf.trim().to_string()));
                    }
                    if matches!(parts.first(), Some(Part::Pattern(_))) {
                        parts.remove(0);
                    }
                    for part in parts.chunks_exact(2) {
                        if let (Part::Id(ids), Part::Pattern(pattern)) = (&part[0], &part[1]) {
                            if !pattern.is_empty() {
                                for id in ids {
                                    result.push(Rule {
                                        name: rule.name.clone(),
                                        t: RuleType::Header {
                                            matches: HeaderMatches::Matches,
                                            header: Header::Received(*id),
                                            part: HeaderPart::Default,
                                            pattern: if !flags.is_empty() {
                                                format!("(?{flags}){pattern}")
                                            } else {
                                                pattern.to_string()
                                            },
                                        },
                                        scores: rule.scores.clone(),
                                        captured_vars: rule.captured_vars.clone(),
                                        required_vars: rule.required_vars.clone(),
                                        description: rule.description.clone(),
                                        priority: rule.priority,
                                        flags: rule.flags.clone(),
                                    });

                                    common_headers
                                        .entry((Header::Received(*id), HeaderPart::Default))
                                        .or_insert_with(HashSet::new)
                                        .insert(rule.name.to_string());
                                }
                            }
                        } else {
                            unreachable!();
                        }
                    }
                }
                RuleType::Header { pattern, .. }
                | RuleType::Body { pattern, .. }
                | RuleType::Full { pattern, .. }
                | RuleType::Uri { pattern, .. } => {
                    let (pattern_, flags, variables) = import_regex(pattern);

                    *pattern = if !flags.is_empty() {
                        format!("(?{flags}){pattern_}")
                    } else {
                        pattern_
                    };
                    rule.required_vars = variables;
                    let cococ = "fd";
                    /*match fancy_regex::Regex::new(pattern) {
                        Ok(r) => {
                            rule.captured_vars = r
                                .capture_names()
                                .enumerate()
                                .filter_map(|(pos, var_name)| {
                                    let var_name = var_name?;
                                    var_to_rule.insert(var_name.to_string(), name.clone());
                                    (var_name.to_string(), pos).into()
                                })
                                .collect();
                        }
                        Err(err) => {
                            eprintln!(
                                "Warning: Invalid regex {} for test {}: {}",
                                pattern, name, err
                            );
                        }
                    }*/

                    if let RuleType::Header {
                        matches: HeaderMatches::Matches | HeaderMatches::NotMatches,
                        header: header @ (Header::MessageId | Header::Name(_) | Header::ToCc),
                        part,
                        ..
                    } = &rule.t
                    {
                        common_headers
                            .entry((header.clone(), *part))
                            .or_insert_with(HashSet::new)
                            .insert(rule.name.to_string());
                    }

                    result.push(rule);
                }
                RuleType::None => {
                    if do_warn {
                        eprintln!("Warning: Test {} has no type: {rule:?}", rule.name);
                    }
                }
                _ => {
                    result.push(rule);
                }
            }
            result
        })
        .collect::<Vec<_>>();
    rules.sort_unstable();

    let mut required_rests: Vec<&str> = vec![];

    let mut tests_done = HashSet::new();
    let mut tests_linked = HashSet::new();
    let mut rules_iter = rules.iter();
    let mut rules_stack = Vec::new();
    let mut rules_sorted = Vec::with_capacity(rules.len());

    // Sort rules by meta
    loop {
        while let Some(rule) = rules_iter.next() {
            let in_linked = !required_rests.is_empty();
            if tests_done.contains(&rule.name)
                || (in_linked && !required_rests.contains(&rule.name.as_str()))
            {
                continue;
            }
            tests_done.insert(&rule.name);
            if in_linked {
                tests_linked.insert(&rule.name);
            }

            let new_required_tests = match &rule.t {
                RuleType::Meta { expr } if rule.score() != 0.0 || rule.is_subrule() => expr
                    .tokens
                    .iter()
                    .filter_map(|t| match &t {
                        Token::Tag(t) if !tests_done.contains(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => rule
                    .required_vars
                    .iter()
                    .filter_map(|required_var| {
                        if let Some(required_test) = var_to_rule.get(required_var) {
                            if !tests_done.contains(required_test) {
                                Some(required_test.as_str())
                            } else {
                                None
                            }
                        } else {
                            eprintln!(
                                "Warning: Variable {required_var:?} not found for test {:?}",
                                rule.name
                            );
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            };

            if !new_required_tests.is_empty() {
                rules_stack.push((rule, rules_iter, required_rests));
                rules_iter = rules.iter();
                required_rests = new_required_tests;
            } else {
                rules_sorted.push(rule);
            }
        }

        if let Some((prev_rule, prev_rules_iter, prev_required_tests)) = rules_stack.pop() {
            rules_sorted.push(prev_rule);
            rules_iter = prev_rules_iter;
            required_rests = prev_required_tests;
        } else {
            break;
        }
    }

    // Generate script
    let mut script = String::from(concat!(
        "require [\"variables\", \"include\", \"regex\", \"body\", ",
        "\"vnd.stalwart.foreveryline\", \"vnd.stalwart.eval\",",
        " \"vnd.stalwart.plugins\"];\n\n",
        "set \"score\" \"0.0\";\n",
        "set \"spam_score\" \"5.0\";\n",
        "set \"awl_factor\" \"0.5\";\n",
        "set \"body\" \"${body.to_text}\";\n",
        "set \"body_len\" \"${body.len()}\";\n",
        "set \"body_ucc\" \"${count_uppercase(body)}\";\n",
        "set \"body_lcc\" \"${count_lowercase(body)}\";\n",
        "set \"body_ul_ratio\" \"${body_ucc / (body_ucc + body_lcc)}\";\n",
        "set \"headers_raw\" \"${header.*.raw}\";\n",
        "set \"headers_text\" \"${header.*.text}\";\n",
        "set \"thread_name\" \"${header.subject.thread_name()}\";\n",
        "set \"sent_date\" \"${header.date.date}\";\n",
        "set \"mail_from\" \"${envelope.from}\";\n",
        "if eval \"mail_from.is_empty()\" {\n",
        "\tset \"mail_from\" \"postmaster@${env.helo_domain}\";\n",
        "}\n",
        "set \"mail_from_domain\" \"${mail_from.domain_part()}\";\n",
        "set \"from\" \"${header.from.addr}\";\n",
        "set \"from_domain\" \"${from.domain_part()}\";\n",
        "set \"from_name\" \"${header.from.name.trim()}\";\n",
        "\n"
    ));

    // Print grouped rules
    let mut descriptions: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut processed_rules = HashSet::new();
    for ((header, part), rule_names) in common_headers {
        script.push_str("foreveryline \"${");
        let mut add_to_processed = true;
        match &header {
            Header::All => {
                script.push_str(match part {
                    HeaderPart::Raw => "headers_raw",
                    _ => "headers_text",
                });
            }
            Header::MessageId => {
                script.push_str(concat!(
                    "header.message-id:resent-message-id:",
                    "x-message-id:x-original-message-id[*].id[*]"
                ));
            }
            Header::ToCc => {
                script.push_str("header.to:cc[*]");
                script.push_str(match part {
                    HeaderPart::Name => ".name[*]",
                    HeaderPart::Addr => ".addr[*]",
                    HeaderPart::Raw => ".raw",
                    HeaderPart::Default => ".text",
                });
            }
            Header::Name(name) => {
                script.push_str("header.");
                script.push_str(name);
                script.push_str("[*]");
                script.push_str(match part {
                    HeaderPart::Name => ".name[*]",
                    HeaderPart::Addr => ".addr[*]",
                    HeaderPart::Raw => ".raw",
                    HeaderPart::Default => "",
                });
            }
            Header::Received(rcvd) => {
                script.push_str("header.received[*].rcvd.");
                script.push_str(match rcvd {
                    ReceivedPart::From => "from",
                    ReceivedPart::FromIp => "ip",
                    ReceivedPart::FromIpRev => "iprev",
                    ReceivedPart::Protocol => "with",
                    ReceivedPart::By => "by",
                    ReceivedPart::For => "for",
                    ReceivedPart::Ident => "ident",
                    ReceivedPart::Id => "id",
                });
                if matches!(
                    rcvd,
                    ReceivedPart::From | ReceivedPart::FromIp | ReceivedPart::FromIpRev
                ) {
                    add_to_processed = false;
                }
            }
            Header::EnvelopeFrom => unreachable!(),
        }

        script.push_str("}\" {\n");
        for rule_name in rule_names {
            for rule in &rules {
                if rule.name == rule_name {
                    if rule.score() == 0.0 && !tests_linked.contains(&rule.name) {
                        if do_warn {
                            println!("Warning: Test {} is never linked to.", rule.name);
                        }
                        continue;
                    }
                    if let RuleType::Header {
                        matches,
                        pattern,
                        header: header_,
                        ..
                    } = &rule.t
                    {
                        if header_ != &header {
                            continue;
                        }

                        write!(&mut script, "\tif allof(eval \"!{}\", ", rule_name).unwrap();
                        match matches {
                            HeaderMatches::Matches => script.push_str("string :regex "),
                            HeaderMatches::NotMatches => script.push_str("not string :regex "),
                            HeaderMatches::Exists | HeaderMatches::NotExists => unreachable!(),
                        }
                        script.push_str("\"${line}\" ");
                        write!(&mut script, "{:?})", pattern).unwrap();
                        let spaces = "\t".repeat(2);
                        writeln!(
                            &mut script,
                            " {{\n{spaces}set :local \"{}\" \"1\";",
                            rule.name
                        )
                        .unwrap();

                        for (var_name, pos) in &rule.captured_vars {
                            writeln!(
                                &mut script,
                                "{spaces}set :local \"{}\" \"${{{}}}\";",
                                var_name, pos
                            )
                            .unwrap();
                        }

                        let score = rule.score();
                        if score != 0.0 {
                            script.push_str(&spaces);
                            script.push_str("set \"score\" \"%{score");
                            if score > 0.0 {
                                script.push_str(" + ");
                                script.push_str(&score.to_string());
                            } else {
                                script.push_str(" - ");
                                script.push_str((-score).to_string().as_str());
                            }
                            script.push_str("}\";\n");
                        }
                        script.push_str("\t}\n");
                    } else {
                        unreachable!();
                    }

                    if add_to_processed {
                        processed_rules.insert(rule_name);
                    }
                    break;
                }
            }
        }
        script.push_str("}\n\n");
    }

    for rule in rules_sorted {
        for (lang, text) in &rule.description {
            descriptions
                .entry(lang.to_string())
                .or_default()
                .insert(rule.name.to_string(), text.to_string());
        }

        if rule.score() == 0.0 && !tests_linked.contains(&rule.name) {
            if do_warn {
                eprintln!("Warning: Test {} is never linked to.", rule.name);
            }
            continue;
        } else if !processed_rules.contains(&rule.name) {
            write!(&mut script, "{rule}").unwrap();
        }
    }

    for (lang, texts) in descriptions {
        let mut file = fs::File::create(format!(
            "/Users/me/code/mail-server/_ignore/descriptions_{}.txt",
            lang
        ))
        .unwrap();
        for (name, text) in texts {
            //file.write_all(format!("set {:?} {:?}", name, text).as_bytes());
        }
    }

    fs::write(
        "/Users/me/code/mail-server/_ignore/script.sieve",
        script.as_bytes(),
    )
    .unwrap();

    for (message, unsupported) in [
        ("commands", unsupported_commands),
        ("plugins", unsupported_ifs),
    ] {
        if !unsupported.is_empty() {
            eprintln!("Unsupported {}:", message);
            for (cmd, paths) in unsupported {
                eprintln!(
                    "  {} in {}",
                    cmd,
                    paths
                        .into_iter()
                        .map(|(k, v)| format!(
                            "{}:[{}]",
                            k.file_name().unwrap().to_str().unwrap(),
                            v.into_iter().take(5).collect::<Vec<_>>().join(",")
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
}

impl Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Add comment
        self.description
            .get("en")
            .map(|v| {
                writeln!(f, "# {v} (rank {})", self.priority).unwrap();
            })
            .unwrap_or_else(|| writeln!(f, "# {} (rank {})", self.name, self.priority).unwrap());

        match &self.t {
            RuleType::Header {
                matches: matches @ (HeaderMatches::Exists | HeaderMatches::NotExists),
                header,
                ..
            } => {
                match matches {
                    HeaderMatches::Exists => write!(f, "if exists ")?,
                    HeaderMatches::NotExists => write!(f, "not exists ")?,
                    _ => unreachable!(),
                }
                match header {
                    Header::MessageId => f.write_str(concat!(
                        "[\"Message-Id\",\"Resent-Message-Id\",",
                        "\"X-Message-Id\",\"X-Original-Message-ID\"]"
                    ))?,
                    Header::ToCc => f.write_str("[\"To\",\"Cc\"]")?,
                    Header::Name(name) => write!(f, "{:?}", name)?,
                    _ => unreachable!(),
                }
            }

            RuleType::Header {
                matches,
                header,
                pattern,
                part,
            } => {
                let is_raw = part == &HeaderPart::Raw;
                let is_name = part == &HeaderPart::Name;
                let is_addr = part == &HeaderPart::Addr;

                let pattern = pattern.as_str();
                let matches = *matches;

                f.write_str("if ")?;

                let cmd = if matches!(header, Header::EnvelopeFrom) {
                    "envelope"
                } else if (is_name || is_addr) && !is_raw {
                    "address"
                } else if matches!(header, Header::All | Header::Received(_)) {
                    "string"
                } else {
                    "header"
                };
                match matches {
                    HeaderMatches::Matches => write!(f, "{cmd} :regex ")?,
                    HeaderMatches::NotMatches => write!(f, "not {cmd} :regex ")?,
                    HeaderMatches::Exists | HeaderMatches::NotExists => unreachable!(),
                }
                if !is_raw {
                    if is_name {
                        f.write_str(":name ")?;
                    } else if is_addr {
                        f.write_str(":all ")?;
                    }
                }
                match header {
                    Header::MessageId => f.write_str(concat!(
                        "[\"Message-Id\",\"Resent-Message-Id\",",
                        "\"X-Message-Id\",\"X-Original-Message-ID\"]"
                    ))?,
                    Header::ToCc => f.write_str("[\"To\",\"Cc\"]")?,
                    Header::Name(name) => write!(f, "{:?}", name)?,
                    Header::EnvelopeFrom => f.write_str("\"from\"")?,
                    Header::All => {
                        if is_raw {
                            f.write_str("\"${headers_raw}\"")?
                        } else {
                            f.write_str("\"${headers_text}\"")?
                        }
                    }
                    Header::Received(rcvd) => {
                        f.write_str("\"${env.")?;
                        f.write_str(match rcvd {
                            ReceivedPart::From => "helo_domain",
                            ReceivedPart::FromIp => "remote_ip",
                            ReceivedPart::FromIpRev => "iprev_ptr",
                            _ => unreachable!(),
                        })?;
                        f.write_str("}\"")?;
                    }
                }

                write!(f, " {:?}", pattern)?;

                /*if has_unset {
                    f.write_str(")")?;
                }*/
            }
            RuleType::Body { pattern, raw } => {
                if *raw {
                    write!(f, "if body :raw :regex {pattern:?}")?;
                } else if !self.flags.contains(&TestFlag::NoSubject) {
                    write!(f, "if body :subject :regex {pattern:?}")?;
                } else {
                    write!(f, "if body :regex {pattern:?}")?;
                }
            }
            RuleType::Full { pattern } => {
                write!(f, "if match_full {:?}", pattern)?;
            }
            RuleType::Uri { pattern } => {
                write!(f, "if match_uri {:?}", pattern)?;
            }
            RuleType::Eval { function, params } => {
                match function.as_str() {
                    "check_from_in_auto_welcomelist" | "check_from_in_auto_whitelist" => {
                        f.write_str(concat!(
                        "query :use \"spam\" :set [\"awl_score\", \"awl_count\"] \"SELECT score, count ","FROM awl WHERE sender = ? AND ip = ?\" [\"${from}\", \"%{env.remote_ip}\"];\n",
                        "if eval \"awl_count > 0\" {\n",
                        "\tquery :use \"spam\" \"UPDATE awl SET score = score + ?, count = count + 1 WHERE ","sender = ? AND ip = ?\" [\"%{score}\", \"${from}\", \"%{env.remote_ip}\"];\n",
                        "\tset \"score\" \"%{score + ((awl_score / awl_count) - score) * awl_factor}\";\n",
                        "} else {\n",
                        "\tquery :use \"spam\" \"INSERT INTO awl (score, count, sender, ip) VALUES (?, 1, ?, ?)\""," [\"%{score}\", \"${from}\", \"%{env.remote_ip}\"];\n",
                        "}\n\n",
                    ))?;
                        return Ok(());
                    }
                    "check_from_in_blacklist"
                    | "check_from_in_blocklist"
                    | "check_from_in_default_welcomelist"
                    | "check_from_in_default_whitelist"
                    | "check_from_in_welcomelist"
                    | "check_from_in_whitelist"
                    | "check_to_in_blacklist"
                    | "check_to_in_blocklist"
                    | "check_to_in_welcomelist"
                    | "check_to_in_whitelist"
                    | "check_subject_in_blacklist"
                    | "check_subject_in_blocklist"
                    | "check_subject_in_welcomelist"
                    | "check_subject_in_whitelist"
                    | "check_to_in_more_spam"
                    | "check_to_in_all_spam" => {
                        let mut parts = function.split('_').peekable();
                        parts.next();
                        let header = parts.next().unwrap();
                        parts.next();
                        let mut list = String::new();

                        for part in parts {
                            if !list.is_empty() {
                                list.push('_');
                            }
                            list.push_str(match part {
                                "welcomelist" | "whitelist" => "welcome",
                                "blacklist" | "blocklist" => "block",
                                "more" | "all" | "spam" => part,
                                "default" => "def",
                                _ => unreachable!(),
                            })
                        }

                        let fnc = if header == "subject" {
                            "header"
                        } else {
                            "address"
                        };
                        write!(f, "if {fnc} :list \"{header}\" \"sa/list_{list}_{header}\"")?;
                    }
                    "check_from_in_list" | "check_replyto_in_list" => {
                        let mut header = function.split('_').nth(1).unwrap();
                        if header == "replyto" {
                            header = "reply-to";
                        }
                        #[allow(clippy::print_in_format_impl)]
                        if let Some(list) = params.first() {
                            write!(
                                f,
                                "if address :list \"{header}\" \"sa/list_{}\"",
                                list.to_lowercase()
                            )?;
                        } else {
                            eprintln!("Warning: Found invalid 'check_{header}_in_list' command without parameters.");
                            write!(f, "if false")?;
                        }
                    }
                    "check_for_spf_helo_fail"
                    | "check_for_spf_helo_neutral"
                    | "check_for_spf_helo_none"
                    | "check_for_spf_helo_pass"
                    | "check_for_spf_helo_permerror"
                    | "check_for_spf_helo_softfail"
                    | "check_for_spf_helo_temperror"
                    | "check_for_spf_neutral"
                    | "check_for_spf_none"
                    | "check_for_spf_fail"
                    | "check_for_spf_pass"
                    | "check_for_spf_permerror"
                    | "check_for_spf_softfail"
                    | "check_for_spf_temperror" => {
                        /*let mut parts = function.split('_').rev();
                        let result = parts.next().unwrap();
                        let spf = if parts.next().unwrap() == "helo" {
                            "spf_ehlo"
                        } else {
                            "spf"
                        };
                        write!(f, "if string :is \"${{env.{spf}_result}}\" \"{result}\"")?;*/
                    }
                    "check_arc_signed" => {
                        //f.write_str("if string :value \"ne\" \"${env.arc_result}\" \"none\"")?;
                    }
                    "check_arc_valid" => {
                        //f.write_str("if string :is \"${env.arc_result}\" \"pass\"")?;
                    }
                    "check_dmarc_missing" => {
                        //f.write_str("if string :is \"${env.dmarc_policy}\" \"none\"")?;
                    }
                    "check_dmarc_pass" => {
                        //f.write_str("if string :is \"${env.dmarc_result}\" \"pass\"")?;
                    }
                    "check_dmarc_none" | "check_dmarc_quarantine" | "check_dmarc_reject" => {
                        //let policy = function.split('_').nth(2).unwrap();
                        //write!(f, "if allof(string :is \"${{env.dmarc_result}}\" \"fail\", string :is \"${{env.dmarc_policy}}\" \"{policy}\")")?;
                    }
                    "check_dkim_adsp"
                    | "check_dkim_signall"
                    | "check_dkim_signsome"
                    | "check_dkim_valid_author_sig"
                    | "check_access_database"
                    | "check_body_8bits"
                    | "check_shortcircuit"
                    | "check_suspect_name"
                    | "check_microsoft_executable"
                    | "check_outlook_message_id"
                    | "gated_through_received_hdr_remover"
                    | "check_for_faraway_charset"
                    | "check_for_faraway_charset_in_headers"
                    | "check_all_trusted"
                    | "check_relays_unparseable"
                    | "check_welcomelist_bounce_relays"
                    | "check_whitelist_bounce_relays"
                    | "have_any_bounce_relays"
                    | "check_for_fake_aol_relay_in_rcvd"
                    | "check_for_forged_eudoramail_received_headers"
                    | "check_for_forged_gmail_received_headers"
                    | "check_for_forged_hotmail_received_headers"
                    | "check_for_forged_juno_received_headers"
                    | "check_for_forged_yahoo_received_headers"
                    | "check_for_no_hotmail_received_headers"
                    | "check_stock_info"
                    | "check_abundant_unicode_ratio" => {
                        // ADSP is deprecated (see https://datatracker.ietf.org/doc/status-change-adsp-rfc5617-to-historic/)
                        // check_body_8bits: Not really useful
                        // check_shortcircuit: Not used
                        f.write_str("if false")?;
                    }
                    "check_dkim_dependable" => {
                        //writeln!(f, "set :local \"{}\" \"1\";", self.name)?;
                        //return Ok(());
                    }
                    "check_dkim_signed" => {
                        //f.write_str("if string :value \"ne\" \"${env.dkim_result}\" \"none\"")?;
                    }
                    "check_dkim_testing" => {
                        // score 0
                        //f.write_str("if header :contains \"DKIM-Signature\" \"t=y\"")?;
                    }
                    "check_dkim_valid" => {
                        /*if params.is_empty() {
                            f.write_str("if string :is \"${env.dkim_result}\" \"pass\"")?;
                        } else {
                            f.write_str("if allof(string :is \"${env.dkim_result}\" \"pass\", ")?;
                            if params.len() > 1 {
                                f.write_str("anyof(")?;
                            }
                            for (pos, param) in params.iter().enumerate() {
                                if pos > 0 {
                                    f.write_str(", ")?;
                                }
                                write!(f, "envelope :domain :contains \"from\" {param}")?;
                            }
                            if params.len() > 1 {
                                f.write_str("))")?;
                            } else {
                                f.write_str(")")?;
                            }
                        }*/
                    }
                    "check_dkim_valid_envelopefrom" => {
                        //f.write_str("if allof(string :is \"${env.dkim_result}\" \"pass\", string :is \"${mail_from}\" \"${from}\")")?;
                    }
                    "check_for_def_dkim_welcomelist_from"
                    | "check_for_def_dkim_whitelist_from"
                    | "check_for_dkim_welcomelist_from"
                    | "check_for_dkim_whitelist_from"
                    | "check_for_def_spf_welcomelist_from"
                    | "check_for_def_spf_whitelist_from"
                    | "check_for_spf_welcomelist_from"
                    | "check_for_spf_whitelist_from" => {
                        let list = match (function.contains("dkim"), function.contains("def")) {
                            (true, true) => "def_dkim",
                            (true, false) => "dkim",
                            (false, true) => "def_spf",
                            (false, false) => "spf",
                        };
                        write!(f, "if address :list \"from\" \"sa/list_{list}\"")?;
                    }
                    "check_for_missing_to_header" => {
                        //write!(f, "if not exists \"to\"")?;
                    }
                    "check_for_to_in_subject" => {
                        /*f.write_str("foreveryline \"${header.to[*].addr[*]}\" {\n")?;
                        f.write_str("\tif string :contains \"${header.subject}\" \"${line}\"")?;
                        self.fmt_match(f, 2)?;
                        f.write_str("\t\tbreak;\n\t}\n}\n\n")?;
                        return Ok(());*/
                    }
                    "check_blank_line_ratio" => {
                        /*
                        score = 0
                        let mut params = params.iter();

                        if let (Some(min), Some(max), Some(min_lines)) = (
                            params.next().and_then(param_to_num::<f64>),
                            params.next().and_then(param_to_num::<f64>),
                            params.next().and_then(param_to_num::<i32>),
                        ) {
                            f.write_str(concat!(
                                "set \"body_lines\" \"0\";\n",
                                "set \"body_empty_lines\" \"0\";\n",
                                "foreveryline \"${body}\" {\n",
                                "\tset \"body_lines\" \"%{body_lines + 1}\";\n",
                                "\tif string :is \"${line}\" \"\" {\n",
                                "\t\tset \"body_empty_lines\" \"%{body_empty_lines + 1}\";\n",
                                "\t}\n",
                                "}\n"
                            ))?;

                            write!(
                                f,
                                concat!(
                                    "if eval \"body_lines >= {} && body_empty_lines / body_lines",
                                    " >= {} && body_empty_lines / body_lines <= {}\""
                                ),
                                min_lines,
                                min / 100.0,
                                max / 100.0
                            )?;
                        } else {
                            panic!("Warning: Invalid check_blank_line_ratio");
                        }*/
                    }
                    "check_language" => {
                        f.write_str(concat!(
                            "if not string :list \"all\" \"sa/allowed_languages\" {\n",
                            "\tdetect_lang \"lang\" \"${thread_name} ${body}\";\n",
                            "\tif not string :list \"${lang}\" \"sa/allowed_languages\"",
                        ))?;
                        self.fmt_match(f, 2)?;
                        f.write_str("\t}\n}\n\n")?;
                        return Ok(());
                    }
                    "check_body_length" => {
                        /*write!(
                            f,
                            "if eval \"body_len < {}\" ",
                            params
                                .iter()
                                .next()
                                .and_then(param_to_num::<usize>)
                                .expect("missing body length on check_body_length")
                        )?;*/
                    }
                    "check_equal_from_domains" => {
                        //f.write_str("if not string :is \"${mail_from.subdomain_part()}\" \"${from.subdomain_part()}\"")?;
                    }
                    "check_for_no_rdns_dotcom_helo" => {
                        //f.write_str("if not string :is \"${env.iprev_result}\" [\"pass\", \"\", \"temperror\"]")?;
                    }
                    "helo_ip_mismatch" => {
                        /*f.write_str(concat!(
                            "if allof(not string :is \"${env.iprev_ptr}\" \"\", ",
                            "not string is \"${env.iprev_ptr}\" \"${env.helo_domain}\")"
                        ))?;*/
                    }
                    "subject_is_all_caps" => {
                        //f.write_str("if eval \"thread_name.len() >= 10 && thread_name.count_words() > 1 && thread_name.is_uppercase()\"")?;
                    }
                    "check_for_shifted_date" => {
                        /*let mut params = params.iter();
                        let mut range = [None; 2];
                        for item in range.iter_mut() {
                            let param = params
                                .next()
                                .expect("missing parameter on check_for_shifted_date");
                            if !param.contains("undef") {
                                *item = (param_to_num::<i64>(&param)
                                    .expect("failed to parse parameter on check_for_shifted_date")
                                    * 3600)
                                    .into();
                            }
                        }

                        f.write_str("if eval \"sent_date > 0 && ")?;

                        match (range[0], range[1]) {
                            (Some(from), Some(to)) => {
                                write!(
                                    f,
                                    "sent_date - env.now >= {from} && sent_date - env.now < {to}",
                                )?;
                            }
                            (Some(from), None) => {
                                write!(f, "sent_date - env.now >= {from}",)?;
                            }
                            (None, Some(to)) => {
                                write!(f, "sent_date - env.now < {to}",)?;
                            }
                            (None, None) => {
                                panic!("missing parameters on check_for_shifted_date");
                            }
                        }

                        f.write_str("\"")?;*/
                    }
                    "check_ratware_envelope_from" => {
                        /*f.write_str(concat!(
                            "set \"env_from_local\" \"${mail_from.local_part()}\";\n",
                            "set \"to_local\" \"${header.to.addr.local_part()}\";\n",
                            "set \"to_domain\" \"${header.to.addr.domain_part()}\";\n",
                            "if all_of(",
                            "not string :is \"${env_from_local}\" \"\", ",
                            "not string :is \"${to_local}\" \"\", ",
                            "not string :is \"${to_domain}\" \"\", ",
                            "string :contains \"${env_from_local}\" \"${to_domain}\", ",
                            "string :contains \"${env_from_local}\" \"${to_local}\")"
                        ))?;*/
                    }
                    "check_ratware_name_id" => {
                        /*f.write_str(concat!(
                            "if header :contains ",
                            "[\"Message-Id\",\"Resent-Message-Id\",",
                            "\"X-Message-Id\",\"X-Original-Message-ID\"] ",
                            "\"${from}\"",
                        ))?;*/
                    }
                    "check_mailfrom_matches_rcvd" => {
                        /*f.write_str(
                            "if string :contains \"${env.helo_domain}\" \"${mail_from_domain}\"",
                        )?;*/
                    }

                    "check_unresolved_template" => {
                        /*f.write_str(concat!(
                            "foreveryline \"${headers_raw}\" {\n",
                            "\tif allof(string :regex \"${line}\" \"%[A-Z][A-Z_-]\", ",
                            "not string :regex \"${line}\" \"(?i)^(?:X-VMS-To|X-UIDL|",
                            "X-Face|To|Cc|From|Subject|References|In-Reply-To|(?:X-|Resent-|",
                            "X-Original-)?Message-Id):\")",
                        ))?;
                        self.fmt_match(f, 2)?;
                        f.write_str("\t\tbreak;\n\t}\n}\n\n")?;
                        return Ok(());*/
                    }
                    "check_for_matching_env_and_hdr_from" => {
                        //f.write_str("if string :is \"${mail_from}\" \"${from}\"")?;
                    }
                    "check_fromname_equals_replyto" => {
                        //f.write_str("if string :is \"${from_name}\" \"${header.reply-to.addr}\"")?;
                    }
                    "check_fromname_equals_to" => {
                        /*f.write_str(concat!(
                            "foreveryline \"${header.to[*].addr[*]}\" {\n",
                            "\tif string :is \"${from_name}\" \"${line}\"",
                        ))?;
                        self.fmt_match(f, 2)?;
                        f.write_str("\t\tbreak;\n\t}\n}\n\n")?;
                        return Ok(());*/
                    }
                    "check_fromname_spoof" => {
                        /*f.write_str(concat!(
                            "if eval \"is_email(from_name) && ",
                            "domain_name_part(from_name) != domain_name_part(from)\")",
                        ))?;*/
                    }
                    "check_header_count_range" => {
                        /*let mut params = params.iter();
                        let hdr_name = params
                            .next()
                            .expect("missing parameters for check_header_count_range")
                            .to_lowercase();
                        let range_from = params
                            .next()
                            .and_then(param_to_num::<u32>)
                            .expect("missing parameters for check_header_count_range from");
                        let range_to = params
                            .next()
                            .and_then(param_to_num::<u32>)
                            .expect("missing parameters for check_header_count_range to");

                        if range_to > 100 {
                            write!(
                                f,
                                "if eval \"count(header.{hdr_name}[*].raw) >= {range_from}\""
                            )?;
                        } else {
                            write!(f, "if eval \"count(header.{hdr_name}[*].raw) >= {range_from} && header.{hdr_name}[*].raw.count() < {range_to}\"")?;
                        }*/
                    }
                    "check_illegal_chars" => {
                        /*let mut params = params.iter();
                        let hdr_name = params
                            .next()
                            .expect("missing parameters for check_illegal_chars");
                        let hdr_name = if hdr_name.contains("ALL") {
                            "headers_raw".to_string()
                        } else {
                            format!("header.{}[*].raw", hdr_name.to_lowercase())
                        };
                        let ratio = params
                            .next()
                            .and_then(param_to_num::<f64>)
                            .expect("missing parameters for check_illegal_chars ratio");
                        let count = params
                            .next()
                            .and_then(param_to_num::<u32>)
                            .expect("missing parameters for check_illegal_chars count");
                        writeln!(f, "set \"c_count\" \"%{{{hdr_name}.count_chars()}}\";\n")?;
                        writeln!(
                            f,
                            "set \"i_count\" \"%{{{hdr_name}.count_control_chars()}}\";\n"
                        )?;
                        writeln!(
                            f,
                            "if eval \"i_count > {count} && i_count / c_count > {ratio}\""
                        )?;*/
                    }
                    "check_freemail_from" => {
                        f.write_str(concat!(
                            "if anyof(address :domain :list ",
                            "[\"From\", \"Resent-From\", \"Envelope-Sender\",",
                            "\"Resent-Sender\", \"X-Envelope-From\"] \"sa/freemail_domains\", ",
                            "envelope :list \"from\" \"sa/freemail_domains\")",
                        ))?;
                    }
                    "check_freemail_header" => {
                        let header = strip_quotes(
                            params
                                .iter()
                                .next()
                                .expect("missing header name for check_freemail_header"),
                        );
                        if header.contains("EnvelopeFrom") {
                            f.write_str(
                                "if string :list \"%{mail_from_domain}\" \"sa/freemail_domains\"",
                            )?;
                        } else {
                            writeln!(
                                f,
                                "if address :domain \"{}\" \"sa/freemail_domains\"",
                                header
                                    .split_once(':')
                                    .map_or(header, |v| v.1)
                                    .to_lowercase()
                            )?;
                        }
                    }
                    "check_no_relays" => {}
                    "check_for_forged_received_trail" => {
                        /*f.write_str(concat!(
                            "if allof(string :value \"${env.iprev_ptr}\" \"\", ",
                            "string :value \"ne\" \"%{env.helo_domain}\" \"${env.iprev_ptr}\")"
                        ))?;*/
                    }

                    "check_for_mime_html_only"
                    | "check_for_mime_html"
                    | "multipart_alternative_difference"
                    | "multipart_alternative_difference_count"
                    | "check_ma_non_text"
                    | "check_for_ascii_text_illegal"
                    | "check_mime_multipart_ratio"
                    | "check_msg_parse_flags"
                    | "tvd_vertical_words"
                    | "check_base64_length"
                    | "check_for_uppercase"
                    | "check_for_mime"
                    | "html_charset_faraway" => {
                        // Handled externally
                        return Ok(());
                        //f.write_str("if eval \"header.content-type == 'text/html'\"")?;
                        /*

                         let params = params
                            .iter()
                            .next()
                            .expect("missing parameter for check_msg_parse_flags");
                        if params.contains("mime_epilogue_exists") {
                            f.write_str("if eval \"header.content-type.type == 'multipart' && !ends-with(trim(part.raw), '--')\"")?;
                        } else if params.contains("missing_mime_headers")
                            || params.contains("missing_head_body_separator")
                        {
                            let c = "implemented in loop";
                        } else {
                            panic!("Warning: Invalid check_msg_parse_flags {:?}", params);
                        }
                         */
                    }

                    _ => {
                        write!(f, "if {function}")?;
                        for param in params {
                            f.write_str(" ")?;
                            if let Some(param) =
                                param.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))
                            {
                                write!(f, "\"{param}\"")?;
                            } else if param.starts_with('\"') {
                                f.write_str(param)?;
                            } else {
                                write!(f, "\"{param}\"")?;
                            }
                        }
                    }
                }
            }
            RuleType::Meta { expr } => {
                write!(f, "if eval {:?}", expr.expr.trim())?;
            }
            RuleType::None => {
                f.write_str("if false")?;
            }
        }

        self.fmt_match(f, 1)?;
        f.write_str("}\n\n")
    }
}

impl Rule {
    fn fmt_match(&self, f: &mut std::fmt::Formatter<'_>, depth: usize) -> std::fmt::Result {
        let spaces = "\t".repeat(depth);
        writeln!(f, " {{\n{spaces}set :local \"{}\" \"1\";", self.name)?;

        for (var_name, pos) in &self.captured_vars {
            writeln!(f, "{spaces}set :local \"{}\" \"${{{}}}\";", var_name, pos)?;
        }

        let score = self.score();
        if score != 0.0 {
            f.write_str(&spaces)?;
            f.write_str("set \"score\" \"%{score")?;
            if score > 0.0 {
                f.write_str(" + ")?;
                score.fmt(f)?;
            } else {
                f.write_str(" - ")?;
                (-score).fmt(f)?;
            }
            f.write_str("}\";\n")?;
        }

        Ok(())
    }
}

fn param_to_num<N: FromStr>(text: impl AsRef<str>) -> Option<N> {
    strip_quotes(text.as_ref()).parse::<N>().ok()
}

fn strip_quotes(text: &str) -> &str {
    text.strip_prefix('\"')
        .and_then(|v| v.strip_suffix('\"'))
        .unwrap_or(text)
}
