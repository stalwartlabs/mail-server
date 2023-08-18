use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Display, Write},
    fs::{self},
    path::PathBuf,
};

use super::{
    meta::MetaExpression,
    utils::{fix_broken_regex, replace_tags},
    Header, HeaderMatches, HeaderPart, Rule, RuleType, TestFlag, Token, UnwrapResult,
};

const VERSION: f64 = 4.000000;

static IF_TRUE: [&str; 57] = [
    "Mail::SpamAssassin::Plugin::DKIM",
    "Mail::SpamAssassin::Plugin::SPF",
    "Mail::SpamAssassin::Plugin::ASN",
    "Mail::SpamAssassin::Plugin::AWL",
    "Mail::SpamAssassin::Plugin::AccessDB",
    "Mail::SpamAssassin::Plugin::AntiVirus",
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
    "Mail::SpamAssassin::Plugin::Shortcircuit",
    "Mail::SpamAssassin::Plugin::TextCat",
    "Mail::SpamAssassin::Plugin::TxRep",
    "Mail::SpamAssassin::Plugin::URIDNSBL",
    "Mail::SpamAssassin::Plugin::URIEval",
    "Mail::SpamAssassin::Plugin::VBounce",
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

static IF_FALSE: [&str; 1] = ["Mail::SpamAssassin::Plugin::WhiteListSubject"];

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

pub fn import_spamassassin(path: PathBuf, extension: String, do_warn: bool, validate_regex: bool) {
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
            let todo = "GB_TO_ADDR caca";

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
                                    if_unset: None,
                                    pattern: String::new(),
                                    part: vec![],
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
                                rule.t = RuleType::Header {
                                    matches: match op {
                                        "=~" => HeaderMatches::Matches,
                                        "!~" => HeaderMatches::NotMatches,
                                        _ => {
                                            eprintln!(
                                                "Warning: Invalid operator {op:?} on {}, line {}",
                                                path.display(),
                                                line_num
                                            );
                                            continue;
                                        }
                                    },
                                    header: match header {
                                        "ALL" => Header::All,
                                        "MESSAGEID" => Header::MessageId,
                                        "ALL-EXTERNAL" => Header::AllExternal,
                                        "EnvelopeFrom" => Header::EnvelopeFrom,
                                        "ToCc" => Header::ToCc,
                                        _ => Header::Name(header.to_string()),
                                    },
                                    if_unset: pattern.rsplit_once("[if-unset:").and_then(
                                        |(new_pattern, if_unset)| {
                                            pattern = new_pattern.trim();
                                            if let Some(if_unset) =
                                                if_unset.strip_suffix(']').map(|v| v.trim())
                                            {
                                                if_unset.to_string().into()
                                            } else {
                                                eprintln!(
                                                    "Warning: Failed to parse if_unset for header command on {}, line {}",
                                                    path.display(),
                                                    line_num
                                                );
                                                None
                                            }
                                        },
                                    ),
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
                        let expr = MetaExpression::from_meta(expression);
                        /*if tokens.tokens.contains(&Token::Divide) {
                            println!(
                                "->: {expression}\n{:?}\n<-: {}",
                                tokens
                                    .tokens
                                    .iter()
                                    .zip(tokens.token_depth.iter())
                                    .collect::<Vec<_>>(),
                                String::from(tokens.clone())
                            );
                            std::process::exit(1);
                        }*/
                        rules.entry(test_name.to_string()).or_default().t = RuleType::Meta { expr };
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
                        if validate_regex {
                            if let Err(err) = fancy_regex::Regex::new(&pattern) {
                                eprintln!(
                                    "Warning: Invalid regex {pattern:?} on {}, line {}: {}",
                                    path.display(),
                                    line_num,
                                    err
                                );
                            }
                        }
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
                | "ok_languages"
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

    let mut rules = rules
        .into_iter()
        .filter_map(|(name, mut rule)| {
            if !matches!(rule.t, RuleType::None) {
                if validate_regex {
                    if let Some(pattern) = rule.t.pattern() {
                        if let Err(err) = fancy_regex::Regex::new(pattern) {
                            eprintln!(
                                "Warning: Invalid regex {} for test {}: {}",
                                pattern, name, err
                            );
                        }
                    }
                }
                rule.name = name;
                rule.into()
            } else {
                if do_warn {
                    eprintln!("Warning: Test {name} has no type: {rule:?}");
                }
                None
            }
        })
        .collect::<Vec<_>>();
    rules.sort_unstable();

    let no_meta = MetaExpression::default();
    let mut meta = &no_meta;

    let mut tests_done = HashSet::new();
    let mut tests_linked = HashSet::new();
    let mut rules_iter = rules.iter();
    let mut rules_stack = Vec::new();
    let mut rules_sorted = Vec::with_capacity(rules.len());

    // Sort rules by meta
    loop {
        while let Some(rule) = rules_iter.next() {
            let in_meta = !meta.tokens.is_empty();
            if tests_done.contains(&rule.name)
                || (in_meta
                    && !meta
                        .tokens
                        .iter()
                        .any(|t| matches!(&t.token, Token::Tag(n) if n == &rule.name)))
            {
                continue;
            }
            tests_done.insert(&rule.name);
            if in_meta {
                tests_linked.insert(&rule.name);
            }

            match &rule.t {
                RuleType::Meta { expr } if rule.score() != 0.0 => {
                    rules_stack.push((meta, rule, rules_iter));
                    rules_iter = rules.iter();
                    meta = expr;
                }
                _ => {
                    rules_sorted.push(rule);
                    //write!(&mut script, "{rule}").unwrap();
                }
            }
        }

        if let Some((prev_meta, prev_rule, prev_rules_iter)) = rules_stack.pop() {
            rules_sorted.push(prev_rule);
            //write!(&mut script, "{prev_rule}").unwrap();
            rules_iter = prev_rules_iter;
            meta = prev_meta;
        } else {
            break;
        }
    }

    // Generate script
    let mut script = String::new();
    let mut rules_iter = rules_sorted.iter();

    while let Some(&rule) = rules_iter.next() {
        if rule.score() == 0.0 && !tests_linked.contains(&rule.name) {
            if do_warn {
                eprintln!("Warning: Test {} is never linked to.", rule.name);
            }
            continue;
        }

        // Calculate forward scores
        let (score_pos, score_neg) =
            rules_iter
                .clone()
                .fold((0.0, 0.0), |(acc_pos, acc_neg), rule| {
                    let score = rule.score();
                    if score > 0.0 {
                        (acc_pos + score, acc_neg)
                    } else if score < 0.0 {
                        (acc_pos, acc_neg + score)
                    } else {
                        (acc_pos, acc_neg)
                    }
                });
        let mut rule = rule.clone();
        rule.forward_score_neg = score_neg;
        rule.forward_score_pos = score_pos;

        write!(&mut script, "{rule}").unwrap();
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
                matches,
                header: header @ (Header::All | Header::AllExternal),
                if_unset,
                pattern,
                part,
            } => {
                write!(
                    f,
                    "if vnd.stalwart.eval(\"match_all_headers\", \"{}\", {:?})",
                    if header == &Header::All {
                        "all"
                    } else {
                        "all-external"
                    },
                    pattern
                )?;
            }
            RuleType::Header {
                matches,
                header,
                if_unset,
                pattern,
                part,
            } => {
                f.write_str("if ")?;
                let cmd = if matches!(header, Header::EnvelopeFrom) {
                    "envelope"
                } else if part.contains(&HeaderPart::Addr) || part.contains(&HeaderPart::Name) {
                    "address"
                } else {
                    "header"
                };
                match matches {
                    HeaderMatches::Matches => write!(f, "{cmd} :regex ")?,
                    HeaderMatches::NotMatches => write!(f, "not {cmd} :regex ")?,
                    HeaderMatches::Exists => write!(f, "{cmd} :contains ")?,
                }
                for part in part {
                    match part {
                        HeaderPart::Name => f.write_str(":name ")?,
                        HeaderPart::Addr => f.write_str(":all ")?,
                        HeaderPart::Raw => f.write_str(":raw ")?,
                    }
                }
                match header {
                        Header::MessageId => f.write_str("[\"Message-Id\",\"Resent-Message-Id\",\"X-Message-Id\",\"X-Original-Message-ID\"]")?,
                        Header::ToCc => f.write_str("[\"To\",\"Cc\"]")?,
                        Header::Name (name) => write!(f, "{:?}", name)?,
                        Header::EnvelopeFrom => f.write_str("\"from\"")?,
                        Header::All |
                        Header::AllExternal => unreachable!(),
                    }

                write!(f, " {:?}", pattern)?;
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
                write!(f, "if vnd.stalwart.eval(\"match_full\", {:?})", pattern)?;
            }
            RuleType::Uri { pattern } => {
                write!(f, "if vnd.stalwart.eval(\"match_uri\", {:?})", pattern)?;
            }
            RuleType::Eval { function, params } => {
                write!(f, "if vnd.stalwart.eval({function:?}")?;
                for param in params {
                    write!(f, ", {param:?}")?;
                }
                f.write_str(")")?;
            }
            RuleType::Meta { expr } => {
                expr.fmt(f)?;
            }
            RuleType::None => {
                f.write_str("if false")?;
            }
        }

        f.write_str(" {\n\tset \"")?;
        f.write_str(&self.name)?;
        f.write_str("\" \"1\";\n")?;
        let score = self.score();

        if score != 0.0 {
            f.write_str("\tset \"score\" \"${score")?;
            if score > 0.0 {
                f.write_str(" + ")?;
                score.fmt(f)?;
            } else {
                f.write_str(" - ")?;
                (-score).fmt(f)?;
            }
            f.write_str("}\";\n\t")?;

            if score > 0.0 {
                if self.forward_score_neg != 0.0 {
                    write!(
                        f,
                        concat!(
                            "if allof(string :value \"ge\" :comparator ",
                            "\"i;ascii-numeric\" \"${{score}}\" \"${{spam_score}}\", ",
                            "string :value \"ge\" :comparator ",
                            "\"i;ascii-numeric\" \"${{score - {:.4}}}\" \"${{spam_score}}\")"
                        ),
                        -self.forward_score_neg
                    )?;
                } else {
                    f.write_str(concat!(
                        "if string :value \"ge\" :comparator ",
                        "\"i;ascii-numeric\" \"${score}\" \"${spam_score}\""
                    ))?;
                }
            } else if self.forward_score_pos != 0.0 {
                write!(
                    f,
                    concat!(
                        "if allof(string :value \"lt\" :comparator ",
                        "\"i;ascii-numeric\" \"${{score}}\" \"${{spam_score}}\", ",
                        "string :value \"lt\" :comparator ",
                        "\"i;ascii-numeric\" \"${{score + {:.4}}}\" \"${{spam_score}}\")"
                    ),
                    self.forward_score_pos
                )?;
            } else {
                f.write_str(concat!(
                    "if string :value \"lt\" :comparator ",
                    "\"i;ascii-numeric\" \"${score}\" \"${spam_score}\""
                ))?;
            }
            f.write_str(" {\n\t\treturn;\n\t}\n")?;
        }

        f.write_str("}\n\n")
    }
}
