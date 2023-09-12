require [ "variables", 
          "include", 
          "foreverypart",
          "regex", 
          "body", 
          "reject",
          "vnd.stalwart.foreveryline", 
          "vnd.stalwart.eval", 
          "vnd.stalwart.plugins"];

set "body" "%{body.to_text}";
set "body_len" "%{len(body)}";
set "headers_raw" "%{header.*.raw}";
set "headers_text" "%{header.*.text}";
#set "thread_name" "%{header.subject.thread_name()}";
#set "sent_date" "%{header.date.date}";
#set "mail_from" "%{envelope.from}";
#if eval "mail_from.is_empty()" {
#	set "mail_from" "postmaster@${env.helo_domain}";
#}
#set "mail_from_domain" "%{mail_from.domain_part()}";
#set "from" "%{header.from.addr}";
#set "from_domain" "%{from.domain_part()}";
#set "from_name" "%{header.from.name.trim()}";

# Message only has text/html MIME parts
if eval "header.content-type == 'text/html'" {
    set "t.MIME_HTML_ONLY" "1";
    set "t.__MIME_HTML" "1";
} 

set "mime_text_html_count" "0";
set "mime_text_plain_count" "0";
set "mime_part_count" "0";

foreverypart {
    set "ct" "%{to_lowercase(header.content-type)}";

    if eval "is_body()" {
        if eval "ct == 'text/plain'" {
            set "mime_text_plain_count" "%{mime_text_plain_count + 1}";
        } elsif eval "ct == 'text/html'" {
            set "mime_text_html_count" "%{mime_text_html_count + 1}";
        } 
    } 
    
    if eval "is_attachment()" {
        # Has a MIME attachment
        set "t.__MIME_ATTACHMENT" "1";
    }
    
    if eval "ct == 'multipart/alternative'" {
        set "text_part" "";
        set "text_part_len" "0";
        set "text_part_words" "";
        set "html_part" "";
        set "html_part_words" "";
        set "html_part_len" "0";

        foreverypart {
            set "ma_ct" "%{to_lowercase(header.content-type)}";

            if eval "text_part_len == 0 && ma_ct == 'text/plain'" {
                set "text_part_len" "%{len(part.text)}";
                set "text_part" "%{part.text}";
                set "text_part_words" "%{tokenize_words(part.text)}";
            } elsif eval "html_part_len == 0 && ma_ct == 'text/html'" {
                set "html_part_len" "%{len(part.text)}";
                set "html_part" "%{html_to_text(part.text)}";
                set "html_part_words" "%{tokenize_words(html_part)}";
            }

            # Multipart/alternative has a no text part
            if eval "!(ma_ct == 'multipart/related' || ma_ct == 'application/rtf' || header.content-type.type == 'text')" {
                set "t.MULTIPART_ALT_NON_TEXT" "1";
            }
        }

        # Multipart message mostly text/html MIME
        if eval "html_part_len > 0 && (text_part_len / html_part_len) >= 0.0 && (text_part_len / html_part_len) < 0.01" {
            set "t.MIME_HTML_MOSTLY" "1";
        }

        # HTML and text parts are different
        if eval "!is_empty(text_part_words) && !is_empty(html_part_words)" {
            if eval "!t.MPART_ALT_DIFF_COUNT" {
                set "ma_count_text" "%{len(text_part_words)}";
                set "ma_count_html" "%{len(html_part_words)}";

                if eval "(ma_count_text > ma_count_html && ma_count_text / ma_count_html > 3) ||
                         (ma_count_html > ma_count_text && ma_count_html / ma_count_text > 3)" {
                    set "t.MPART_ALT_DIFF_COUNT" "1";
                }
            }

            if eval "!t.MPART_ALT_DIFF" {
                if eval "cosine_similarity(text_part_words, html_part_words) < 0.98" {
                    set "t.MPART_ALT_DIFF" "1";
                }
            }
        }

    }

    if eval "eq_ignore_case(header.content-transfer-encoding, 'base64')" {
        # Message has a Base64 encoded MIME part
        set "t.__MIME_BASE64" "1";

        # Some spammers generate base64 encoded parts with a single or a handful of 
        # long lines over the standard length, which hovers around 77 chars on average.
        set "max_b64_len" "%{max_line_len(part.raw)}";
        if eval "max_b64_len == 78 || max_b64_len == 79" {
            set "t.BASE64_LENGTH_78_79" "1";
        } elsif eval "max_b64_len > 79" {
            set "t.BASE64_LENGTH_79_INF" "1";
        }

        # Message text disguised using base64 encoding
        if eval "header.content-type.type == 'text' && is_body() && is_ascii(part.text)" {
            set "t.MIME_BASE64_TEXT" "1";
        }
    } elsif eval "eq_ignore_case(header.content-transfer-encoding, 'quoted-printable')" {
        set "t.__MIME_QP" "1";
        set "t.__MIME_QPC" "%{t.__MIME_QPC + 1}";

        # Quoted-printable line longer than 76 chars
        if eval "max_line_len(part.raw) > 79" {
            set "t.MIME_QP_LONG_LINE" "1";
        }
    }

    # MIME text/plain claims to be ASCII but isn't
    if eval "header.content-type.type == 'text'  
              && ( header.content-transfer-encoding == '' || 
                   eq_ignore_case(header.content-transfer-encoding, '7bit' ) ) 
              && !is_ascii(part.raw)" {
        set "t.PP_MIME_FAKE_ASCII_TEXT" "1";
    }

    # Message has too many MIME parts
    set "mime_part_count" "%{mime_part_count + 1}";
    if eval "mime_part_count > 1000" {
        set "t.MIMEPART_LIMIT_EXCEEDED" "1";
        break;
    }
}

if eval "mime_text_html_count > 0 && mime_text_plain_count == 0" {
    set "t.__MIME_HTML" "1";
}

set "vertical_lines" "0";
set "total_lines" "0";

foreveryline "${body}" {
    # Vertical words in body
    if eval "len(trim(line)) == 1 || (len(line) > 5 && count_spaces(line) / count_chars(line) > 0.8)" {
        set "vertical_lines" "%{vertical_lines + 1}";
    }

    set "total_lines" "%{line_num}";
}

if eval "total_lines > 5 && vertical_lines > total_lines / 2" {
    set "t.__TVD_SPACE_RATIO" "1";
}

# Ratio of uppercase characters in body
if eval "body_len > 200" {
    set "upper_count" "%{count_uppercase(body)}";
    set "lower_count" "%{count_lowercase(body)}";
    set "upper_ratio" "%{upper_count / (upper_count + lower_count)}";

    if eval "upper_ratio > 0.25 && upper_ratio <= 0.5" {
        set "t.__UPPERCASE_25_50" "1";
    } elsif eval "upper_ratio > 0.50 && upper_ratio <= 0.75" {
        set "t.__UPPERCASE_50_75" "1";
    } elsif eval "upper_ratio > 0.75" {
        set "t.__UPPERCASE_75_100" "1";
    }
}

# Check for a forged received trail
if eval "!is_empty(env.iprev_ptr) && !eq_ignore_case(env.helo_domain, env.iprev_ptr)" {
    set "t.__FORGED_RCVD_TRAIL" "1";
} else {
    foreveryline "${header.received[*].rcvd.iprev}" {
        if eval "!is_empty(line)" {
            set "helo_domain" "%{received_part(line_num, 'from')}";
            if eval "!is_empty(helo_domain) && !eq_ignore_case(helo_domain, line)" {
                set "t.__FORGED_RCVD_TRAIL" "1";
                break;
            }
        }
    }
}
