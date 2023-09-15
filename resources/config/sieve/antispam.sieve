require [ "variables", 
          "include", 
          "foreverypart",
          "regex", 
          "body", 
          "reject",
          "vnd.stalwart.while", 
          "vnd.stalwart.eval", 
          "vnd.stalwart.plugins"];

set "body" "%{body.to_text}";
set "body_len" "%{len(body)}";
set "headers_raw" "%{header.*.raw}";
set "headers_text" "%{header.*.text}";

# Message only has text/html MIME parts
if eval "header.content-type == 'text/html'" {
    set "t.MIME_HTML_ONLY" "1";
    set "t.__MIME_HTML" "1";
} 

# Part count
set "mime_text_html_count" "0";
set "mime_text_plain_count" "0";
set "mime_part_count" "0";

# Inline image count and area
set "mime_gif_count" "0";
set "mime_png_count" "0";
set "mime_jpg_count" "0";
set "mime_img_count" "0";
set "mime_img_area" "0";
set "mime_gif_area" "0";
set "mime_png_area" "0";

foreverypart {
    set "ct" "%{to_lowercase(header.content-type)}";

    if eval "is_body()" {
        if eval "ct == 'text/plain'" {
            set "mime_text_plain_count" "%{mime_text_plain_count + 1}";
        } elsif eval "ct == 'text/html'" {
            set "mime_text_html_count" "%{mime_text_html_count + 1}";
            set "t.HTML_MESSAGE" "1";

            # Tokenize HTML
            set "html_tokens" "${tokenize_html(part.text)}";
            set "html_char_count" "0";
            set "html_space_count" "0";
            set "html_img_area" "0";
            set "in_head" "0";
            set "in_body" "0";
            set "in_center" "0";
            set "in_title" "0";
            set "in_anchor" "0";
            set "in_anchor_href" "";

            set "i" "%{len(html_tokens)}";
            while "i" {
                set "i" "%{i - 1}";
                set "line" "%{html_tokens[i]}";

                # Tokens starting with '_' are text nodes
                if eval "starts_with(line, '_')" {
                    if eval "in_head == 0" {
                        set "html_char_count" "%{html_char_count + count_chars(line) - 1}";
                        set "html_space_count" "%{html_space_count + count_spaces(line)}";
                    }
                    set "text_len" "%{len(line) - 1}";
                    if eval "in_title && !is_empty(header.subject) && text_len / len(header.subject) > 3.5" {
                        set "t.__HTML_TITLE_SUBJ_DIFF" "1";
                    }
                    if eval "text_len == 120" {
                        set "t.__HTML_TITLE_120" "1";
                    }
                    if eval "in_anchor && 
                             !is_empty(in_anchor_href) && 
                             contains_ignore_case(line, 'http') && 
                             uri_part(trim(substring(line, 1, text_len)), 'scheme_host') != in_anchor_href" {
                        set "t.HTTPS_HTTP_MISMATCH" "1";
                    }
                } elsif eval "starts_with(line, '<!--')" {
                    set "t.__COMMENT_EXISTS" "1";
                    if eval "len(line) - 4 <= 6" {
                        set "t.HTML_COMMENT_SHORT" "1";
                    } elsif eval "starts_with(line, '<!-- saved from url=')" {
                        set "t.HTML_COMMENT_SAVED_URL" "1";
                    }
                } elsif eval "starts_with(line, '<img')" {
                    set "width" "%{html_attr_int(line, 'width', 800)}";
                    set "height" "%{html_attr_int(line, 'height', 600)}";

                    if "!width" {
                        set "width" "200";
                    }
                    if "!height" {
                        set "height" "200";
                    }

                    set "html_img_area" "%{html_img_area + (width * height)}";

                    if eval "in_anchor" {
                        set "t.__HTML_LINK_IMAGE" "1";
                    }

                } elsif eval "starts_with(line, '<bgsound')" {
                    set "t.HTML_TAG_EXIST_BGSOUND" "1";
                } elsif eval "starts_with(line, '<center')" {
                    set "t.__TAG_EXISTS_CENTER" "1";
                    set "in_center" "${in_center + 1}";
                } elsif eval "starts_with(line, '</center')" {
                    set "in_center" "${in_center - 1}";
                } elsif eval "starts_with(line, '<body')" {
                    set "t.__TAG_EXISTS_BODY" "1";
                    set "in_body" "${in_body + 1}";
                } elsif eval "starts_with(line, '</body')" {
                    set "in_body" "${in_body - 1}";
                } elsif eval "starts_with(line, '<head')" {
                    set "t.__TAG_EXISTS_HEAD" "1";
                    set "in_head" "${in_head + 1}";
                } elsif eval "starts_with(line, '</head')" {
                    set "in_head" "%{in_head - 1}";
                } elsif eval "starts_with(line, '<title')" {
                    set "in_title" "1";
                } elsif eval "in_title && starts_with(line, '</title')" {
                    set "in_title" "0";
                } elsif eval "starts_with(line, '<a ')" {
                    set "in_anchor" "1";
                    set "in_anchor_href" "%{uri_part(trim(html_attr(line, 'href')), 'scheme_host')}";
                } elsif eval "in_anchor && starts_with(line, '</a')" {
                    set "in_anchor" "0";
                } elsif eval "starts_with(line, '<html')" {
                    set "t.__TAG_EXISTS_HTML" "1";
                } elsif eval "starts_with(line, '<meta')" {
                    set "t.__TAG_EXISTS_META" "1";
                } elsif eval "starts_with(line, '<style')" {
                    set "t.__TAG_EXISTS_STYLE" "1";
                } elsif eval "starts_with(line, '<script')" {
                    set "t.__TAG_EXISTS_SCRIPT" "1";
                } elsif eval "starts_with(line, '<iframe')" {
                    if eval "!is_empty(html_attr(line, 'src'))" {
                        set "t.HTML_IFRAME_SRC" "1";
                    }
                } elsif eval "starts_with(line, '<embed') || starts_with(line, '<object')" {
                    set "t.HTML_EMBEDS" "1";
                } elsif eval "starts_with(line, '<form')" {
                    if eval "starts_with(html_attr(line, 'action'), 'mailto')" {
                        set "t.HTML_FORMACTION_MAILTO" "1";
                    }
                }
            }

            if eval "in_head != 0" {
                set "t.HTML_TAG_BALANCE_HEAD" "1";
            }

            if eval "in_body != 0" {
                set "t.HTML_TAG_BALANCE_BODY" "1";
            }

            if eval "in_center != 0" {
                set "t.__HTML_TAG_BALANCE_CENTER" "1";
            }

            if eval "html_img_area > 0" {
                # Calculate image to word ratio
                set "html_img_ratio" "%{(html_char_count - html_space_count) / html_img_area}";
                if eval "html_img_ratio <= 0.002" {
                    set "t.HTML_IMAGE_RATIO_02" "1";
                } elsif html_img_ratio <= 0.004" {
                    set "t.HTML_IMAGE_RATIO_04" "1";
                } elsif eval "html_img_ratio <= 0.006" {
                    set "t.HTML_IMAGE_RATIO_06" "1";
                } elsif eval "html_img_ratio <= '0.008" {
                    set "t.HTML_IMAGE_RATIO_08" "1";
                } 

                # Check for not much raw HTML with images
                if eval "html_char_count <= 400" {
                    set "t.HTML_IMAGE_ONLY_04" "1";
                } elsif eval "html_char_count <= 800" {
                    set "t.HTML_IMAGE_ONLY_08" "1";
                } elsif eval "html_char_count <= 1200 " {
                    set "t.HTML_IMAGE_ONLY_12" "1";
                } elsif eval "html_char_count <= 1600" {
                    set "t.HTML_IMAGE_ONLY_16" "1";
                } elsif eval "html_char_count <= 2000 " {
                    set "t.HTML_IMAGE_ONLY_20" "1";
                } elsif eval "html_char_count <= 2400" {
                    set "t.HTML_IMAGE_ONLY_24" "1";
                } elsif eval "html_char_count <= 2800 " {
                    set "t.HTML_IMAGE_ONLY_28" "1";
                } elsif eval "html_char_count <= 3200 " {
                    set "t.HTML_IMAGE_ONLY_32" "1";
                }
            }

            if eval "html_char_count <= 384" {
                set "t.__HTML_LENGTH_384" "1";
            } elsif eval "html_char_count <= 512" {
                set "t.__HTML_LENGTH_512" "1";
            } elsif eval "html_char_count <= 1024" {
                set "t.__HTML_LENGTH_0000_1024" "1";
            } elsif eval "html_char_count <= 1536" {
                set "t.__HTML_LENGTH_1024_1536" "1";
            } elsif eval "html_char_count <= 2048 " {
                set "t.__HTML_LENGTH_1536_2048" "1";
            }
        } elsif eval "eq_ignore_case(header.content-type.type, 'image')" {
            # Obtain image type and area
            set "img_area" "%{img_metadata('area')}";
            set "img_type" "%{img_metadata('type')}";

            if eval "img_type == 'gif'" {
                set "mime_gif_count" "%{mime_gif_count + 1}";
                set "mime_img_area" "%{mime_img_area + img_area}";
            } elsif eval "img_type =='png'" {
                set "mime_png_count" "%{mime_png_count + 1}";
                set "mime_png_area" "%{mime_png_area + img_area}";
            } elsif eval "img_type == 'jpeg'" {
                set "mime_jpg_count" "%{mime_jpg_count + 1}";
            } else {
                set "mime_img_count" "%{mime_img_count + 1}";
            }
            
            set "mime_img_area" "%{mime_img_area + img_area}";
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

# Message has at least one text/html MIME part
if eval "mime_text_html_count > 0 && mime_text_plain_count == 0" {
    set "t.__MIME_HTML" "1";
}

# Image counts
if eval "mime_gif_count == 1" {
    set "t.__GIF_ATTACH_1" "1";
} elsif eval "mime_gif_count >= 2 {
    set "t.__GIF_ATTACH_2P" "1";
}
if eval "mime_png_count == 1" {
    set "t.__PNG_ATTACH_1" "1";
} elsif eval "mime_png_count >= 2 {
    set "t.__PNG_ATTACH_2P" "1";
}
if eval "mime_jpg_count == 1" {
    set "t.__JPEG_ATTACH_1" "1";
} elsif eval "mime_jpg_count >= 2 {
    set "t.__JPEG_ATTACH_2P" "1";
}
if eval "mime_gif_count + mime_png_count + mime_jpg_count + mime_img_count == 1" {
    set "t.__ONE_IMG" "1";
}

# Image to text ratios
if eval "mime_img_area > 0" {
    if eval "len(body.html) / mime_img_area <= 0.015" {
        # Low rawbody to pixel area ratio
        set "t.__DC_IMG_HTML_RATIO" "1";
    }
    if eval "body_len / mime_img_area <= 0.008" {
        # Low body to pixel area ratio
        set "t.__DC_IMG_TEXT_RATIO" "1";
    }
}
if eval "mime_gif_area >= 180000 && mime_gif_area <= 475000" {
    set "t.__GIF_AREA_180K" "1";
}
if eval "mime_png_area >= 180000 && mime_png_area <= 475000" {
    set "t.__PNG_AREA_180K" "1";
}
if eval "mime_img_area >= 62500 && mime_img_area <= 300000" {
    set "t.__IMG_LE_300K" "1";
}

# Vertical words
set "body_lines" "%{lines(body)}";
set "vertical_lines" "0";
set "total_lines" "len(body_lines)";

set "i" "0";
while "i < total_lines" {
    set "line" "%{body_lines[i]}";
    set "i" "%{i + 1}";

    # Vertical words in body
    if eval "len(trim(line)) == 1 || (len(line) > 5 && count_spaces(line) / count_chars(line) > 0.8)" {
        set "vertical_lines" "%{vertical_lines + 1}";
    }
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
    set "headers" "header.received[*].rcvd.iprev";
    set "headers_len" "%{len(headers)}";
    set "i" "0";
    while "i < headers_len" {
        set "iprev" "%{headers[i]}";
        set "i" "%{i + 1}";

        if eval "!is_empty(iprev)" {
            set "helo_domain" "%{received_part(i, 'from')}";
            if eval "!is_empty(helo_domain) && !eq_ignore_case(helo_domain, iprev)" {
                set "t.__FORGED_RCVD_TRAIL" "1";
                break;
            }
        }
    }
}

# Check for invalid UTF-8 in headers
if eval "!is_header_utf8_valid('Subject')" {
    set "t.__SUBJ_ILLEGAL_CHARS" "1";
}
if eval "!is_header_utf8_valid('From')" {
    set "t.FROM_ILLEGAL_CHARS" "1";
}
if eval "!is_header_utf8_valid('')" {
    set "t.__HEAD_ILLEGAL_CHARS" "1";
}

# Multiple headers
if eval "count(header.subject[*].raw) >= 2" {
    print "head %{header.subject[*].raw}";
    set "t.HEADER_COUNT_SUBJECT" "1";
}
if eval "count(header.content-type[*].raw) >= 2" {
    set "t.HEADER_COUNT_CTYPE" "1";
}

# From name checks
set "mail_from" "%{envelope.from}";
if eval "is_empty(mail_from)" {
	set "mail_from" "postmaster@${env.helo_domain}";
}
set "mail_from_domain" "%{email_part(mail_from, 'domain')}";
set "from" "%{to_lowercase(header.from.addr)}";
set "from_domain" "%{email_part(from, 'domain')}";
set "from_name" "%{to_lowercase(trim(header.from.name))}";

# Envelope from and From: domain match
if eval "eq_ignore_case(from, mail_from)" {
    set "t.__ENV_AND_HDR_FROM_MATCH" "1";
}

# From and EnvelopeFrom 2nd level mail domains are different
if eval "email_part(mail_from, 'subdomain') != email_part(from, 'subdomain')" {
	set "t.HEADER_FROM_DIFFERENT_DOMAINS" "1";
}

if eval "is_email(from_name)" {
    # From:name looks like a spoofed email
    if eval "domain_name_part(from_name) != domain_name_part(from)" {
        set "t.__PLUGIN_FROMNAME_SPOOF" "1";
    }

    # From name is present in Reply-To
    if eval "contains_ignore_case(header.reply-to[*].addr[*], from_name)" {
        set "t.__FROM_EQ_REPLY" "1";
    }
}

set "to_addr" "${header.to[*].addr[*]}";
set "i" "%{len(to_addr)}";
while "i" {
    set "i" "%{i - 1}";
    set "line" "%{to_addr[i]}";

    if eval "!is_empty(line)" {
        # Local part of To: address appears in Subject
        if eval "contains_ignore_case(header.subject, email_part(line, 'local'))" {
            set "t.LOCALPART_IN_SUBJECT" "1";
        }

        # From name is present in To
        if eval "eq_ignore_case(line, from_name)" {
            set "t.__PLUGIN_FROMNAME_EQUALS_TO" "1";
        }
    }
}

# Envelope sender domain matches handover relay domain
if eval "ends-with(env.helo_domain, mail_from_domain)" {
    set "t.__RP_MATCHES_RCVD" "1";
}

# Headers contain an unresolved template 
set "i" "%{len(headers_raw)}";
while "i" {
    set "i" "%{i - 1}";
    set "line" "%{headers_raw[i]}";

	if allof(string :regex "line == '%[A-Z][A-Z_-]", not string :regex "line == '(?i)^(?:X-VMS-To|X-UIDL|X-Face|To|Cc|From|Subject|References|In-Reply-To|(?:X-|Resent-|X-Original-)?Message-Id):") {
		set "t.UNRESOLVED_TEMPLATE" "1";
		break;
	}
}

# ID contains From address
if header :contains ["Message-Id","Resent-Message-Id","X-Message-Id","X-Original-Message-ID"] "${from}" {
	set "t.__RATWARE_NAME_ID" "1";
}

# Bulk email fingerprint
set "env_from_local" "%{email_part(mail_from, 'local')}";
set "to_local" "%{email_part(header.to.addr, 'local')}";
set "to_domain" "%{email_part(header.to.addr, 'domain')}";
if eval "!is_empty(env_from_local) && !is_empty(to_local) && !is_empty(to_domain) && contains(env_from_local, to_domain) && contains(env_from_local, to_local)" {
    set "t.RATWARE_EFROM" "1";
}

# Date checks
set "sent_date" "%{header.date.date}";
if eval "sent_date > 0" {
    set "date_diff" "%{sent_date - env.now}";
    if eval "date_diff >= -21600 && date_diff < -10800" {
        # Date: is 3 to 6 hours before Received: date
        set "t.DATE_IN_PAST_03_06" "1";
    } elsif eval "date_diff >= -43200 && date_diff < -21600" {
        # Date: is 6 to 12 hours before Received: date
        set "t.DATE_IN_PAST_06_12" "1";
    } elsif eval "date_diff >= -86400 && date_diff < -43200" {
        # Date: is 12 to 24 hours before Received: date
        set "t.DATE_IN_PAST_12_24" "1";
    } elsif eval "date_diff >= -172800 && date_diff < -86400" {
        # Date: is 24 to 48 hours before Received: date
        set "t.DATE_IN_PAST_24_48" "1";
    } elsif eval "date_diff < -345600" {
        # Date: is 96 hours or more before Received: date
        set "t.DATE_IN_PAST_96_XX" "1";
    } elsif eval "date_diff >= 10800 && date_diff < 21600" {
        # Date: is 3 to 6 hours after Received: date
        set "t.DATE_IN_FUTURE_03_06" "1";
    } elsif eval "date_diff >= 21600 && date_diff < 43200" {
        # Date: is 6 to 12 hours after Received: date
        set "t.DATE_IN_FUTURE_06_12" "1";
    } elsif eval "date_diff >= 43200 && date_diff < 86400" {
        # Date: is 12 to 24 hours after Received: date
        set "t.DATE_IN_FUTURE_12_24" "1";
    } elsif eval "date_diff >= 86400 && date_diff < 172800" {
        # Date: is 24 to 48 hours after Received: date
        set "t.DATE_IN_FUTURE_24_48" "1";
    } elsif eval "date_diff >= 172800 && date_diff < 345600" {
        # Date: is 48 to 96 hours after Received: date
        set "t.DATE_IN_FUTURE_48_96" "1";
    } elsif eval "date_diff >= 10512000" {
        # Date: is over 4 months after Received: date
        set "t.DATE_IN_FUTURE_Q_PLUS" "1";
    }
}

# Subject is all capitals
set "thread_name" "%{thread_name(header.subject)}";
if eval "len(thread_name) >= 10 && count(tokenize_words(thread_name)) > 1 && is_uppercase(thread_name)" {
	set "t.SUBJ_ALL_CAPS" "1";
}

# Received: HELO and IP do not match, but should
if eval "!is_empty(env.iprev_ptr) && env.iprev_ptr != env.helo_domain" {
	set "t.RCVD_HELO_IP_MISMATCH" "1";
}

# Host has no rDNS
if not string :is "${env.iprev_result}" ["pass", "", "temperror"] {
	set "t.__RDNS_NONE" "1";
}

# The length of the body of the email is less than 128 bytes.
if eval "body_len < 128"  {
	set "t.__KAM_BODY_LENGTH_LT_128" "1";
}
# The length of the body of the email is less than 512 bytes.
if eval "body_len < 512"  {
	set "t.__KAM_BODY_LENGTH_LT_512" "1";
}
# The length of the body of the email is less than 1024 bytes.
if eval "body_len < 1024"  {
	set "t.__KAM_BODY_LENGTH_LT_1024" "1";
}

# Missing To: header
if eval "is_empty(header.to)" {
	set "t.MISSING_HEADERS" "1";
}

# DKIM checks
set "t.__DKIM_DEPENDABLE" "1";
if "!is_empty(env.dkim_result) && env.dkim_result != 'none'" {
    # Message has a DKIM signature, not necessarily valid
	set "t.DKIM_SIGNED" "1";

    # Message has a valid DKIM signature from envelope-from domain
    if eval "env.dkim_result == 'pass' && mail_from == from" {
        set "t.DKIM_VALID_EF" "1";
    }
}

# SPF checks
if eval "env.spf_result == 'pass'" {
    # SPF: sender matches SPF record
	set "t.SPF_PASS" "1";
} elsif eval "env.spf_result == 'none'" {
    # SPF: sender does not publish an SPF Record
	set "t.SPF_NONE" "1";
} elsif eval "env.spf_result == 'neutral'" {
    # SPF: sender does not match SPF record (neutral)
	set "t.SPF_NEUTRAL" "1";
} elsif eval "env.spf_result == 'softfail'" {
    # SPF: sender does not match SPF record (softfail)
	set "t.SPF_SOFTFAIL" "1";
} elsif eval "env.spf_result == 'fail'" {
    # SPF: sender does not match SPF record (fail)
	set "t.SPF_FAIL" "1";
}

if eval "env.spf_ehlo_result == 'pass'" {
    # SPF: HELO matches SPF record
	set "t.SPF_HELO_PASS" "1";
} elsif eval "env.spf_ehlo_result == 'fail'" {
    # SPF: HELO does not match SPF record (fail)
	set "t.SPF_HELO_FAIL" "1";
} elsif eval "env.spf_ehlo_result == 'none'" {
    # SPF: HELO does not publish an SPF Record
	set "t.SPF_HELO_NONE" "1";
} elsif eval "env.spf_ehlo_result == 'softfail'" {
    # SPF: HELO does not match SPF record (softfail)
	set "t.SPF_HELO_SOFTFAIL" "1";
} elsif eval "env.spf_ehlo_result == 'neutral'" {
    # SPF: HELO does not match SPF record (neutral)
	set "t.SPF_HELO_NEUTRAL" "1";
}

# ARC checks
if eval "!is_empty(env.arc_result)" {
    if "env.arc_result == 'pass'" {
        # Message has a valid ARC signature
        set "t.ARC_VALID" "1";
    } 
    
    if env.arc_result != 'none'" {
        # Message has a ARC signature
        set "t.ARC_SIGNED" "1";
    }
}

# DMARC checks
if eval "env.dmarc_result == 'pass'" {
    # DMARC pass policy
	set "t.DMARC_PASS" "1";
} elsif eval "env.dmarc_policy == 'none'" {
    # Missing DMARC policy
	set "t.DMARC_MISSING" "1";
} elsif eval "env.dmarc_result == 'fail'" {
    if eval "env.dmarc_policy == 'reject'" {
        # DMARC reject policy
        set "t.DMARC_REJECT" "1";
    } elsif eval "env.dmarc_policy == 'quarantine'" {
        # DMARC quarantine policy
        set "t.DMARC_QUAR" "1";
    } elsif eval "env.dmarc_policy == 'none'" {
        # DMARC none policy
        set "t.DMARC_NONE" "1";
    }
}

# Recipient checks
set "to_cc" "%{dedup(headers.to[*].addr[*] + headers.cc[*].addr[*])}";
if eval "len(to_cc) >= 7 && sort(to_cc, true) == to_cc" {
    # Recipients are sorted alphabetically
    set "t.SORTED_RECIPS" "1";
}
if eval "len(to_cc) => 5" {
    set "i" "%{len(to_cc)}";
    set "hits" "0";
    set "combinations" "0";

    while "i" {
        set "i" "%{i - 1}";
        set "j" "%{i}";
        while "j" {
            set "j" "%{j - 1}";
            set "a" "%{to_lowercase(to_cc[i])}";
            set "b" "%{to_lowercase(to_cc[j])}";

            if "levenshtein_distance(email_part(a, 'local'), email_part(b, 'local')) < 3" {
                set "hits" "%{hits + 1}";
            }

            set "a" "%{email_part(a, 'host')}";
            set "b" "%{email_part(b, 'host')}";

            if "a != b && levenshtein_distance(a, b) < 4" {
                set "hits" "%{hits + 1}";
            }

            set "combinations" "%{combinations + 1}";
        }
    }

    if eval "hits / combinations > 0.65" {
        set "t.SUSPICIOUS_RECIPS" "1";
    }
}
