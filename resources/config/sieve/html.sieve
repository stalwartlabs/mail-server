
# Message only has text/html MIME parts
if eval "header.content-type == 'text/html'" {
    set "t.MIME_HTML_ONLY" "1";
} 

foreverypart {
    if eval "is_body() && eq_ignore_case(header.content-type, 'text/html')" {
        # Tokenize HTML
        set "html_tokens" "%{tokenize_html(part.text)}";
        set "html_tokens_len" "%{len(html_tokens)}";
        set "html_char_count" "0";
        set "html_space_count" "0";
        set "html_img_words" "0";
        set "html_words" "0";
        set "has_link_to_img" "0";
        set "has_uri" "0";
        set "has_text" "0";
        set "in_head" "0";
        set "in_body" "0";
        set "in_anchor" "0";
        set "in_anchor_href" "";

        set "i" "0";
        while "i < html_tokens_len" {
            set "token" "%{html_tokens[i]}";
            set "i" "%{i + 1}";

            # Tokens starting with '_' are text nodes
            if eval "starts_with(token, '_')" {
                if eval "in_head == 0" {
                    set "html_char_count" "%{html_char_count + count_chars(token)}";
                    set "html_space_count" "%{html_space_count + count_spaces(token)}";

                    set "text" "%{to_lowercase(trim(strip_prefix(token, '_')))}";
                    set "html_words" "%{html_words + len(tokenize_words(text))}";

                    if eval "starts_with(text, 'https://') || starts_with(text, 'http://')" {
                        set "has_uri" "1";
                        if eval "in_anchor && !is_empty(in_anchor_href) &&
                                uri_part(text, 'scheme') != uri_part(in_anchor_href, 'scheme')" {
                            # The anchor text contains a distinct scheme compared to the target URL
                            set "t.HTTP_TO_HTTPS" "1";
                        }
                    } elsif eval "!is_empty(text)" {
                        set "has_text" "1";
                    }
                }
            } elsif eval "starts_with(token, '<img')" {
                set "dimensions" "%{html_attr_size(token, 'width', 800) + html_attr_size(token, 'height', 600)}";

                if eval "in_anchor && dimensions >= 210" {
                    set "has_link_to_img" "1";
                }
                if eval "dimensions > 100" {
                    # We assume that a single picture 100x200 contains approx 3 words of text
                    set "html_img_words" "%{html_img_words + dimensions / 100}";
                }
            } elsif eval "starts_with(token, '<head')" {
                set "in_head" "%{in_head + 1}";
            } elsif eval "starts_with(token, '</head')" {
                set "in_head" "%{in_head - 1}";
            } elsif eval "starts_with(token, '<body')" {
                set "in_body" "%{in_body + 1}";
            } elsif eval "starts_with(token, '</body')" {
                set "in_body" "%{in_body - 1}";
            } elsif eval "starts_with(token, '<a ')" {
                set "in_anchor" "1";
                set "in_anchor_href" "%{trim(html_attr(token, 'href'))}";

                if eval "is_ip_addr(uri_part(in_anchor_href, 'host'))" {
                    # HTML anchor points to an IP address
                    set "t.HTTP_TO_IP" "1";
                }
            } elsif eval "in_anchor && starts_with(token, '</a')" {
                set "in_anchor" "0";
            } elsif eval "starts_with(token, '<link') && 
                            (contains_ignore_case(html_attr(token, 'rel'), 'stylesheet') ||
                             contains_ignore_case(html_attr(token, 'href'), '.css') )" {
                set "t.EXT_CSS" "1";
            }
        }

        # Check for unbalanced tags
        if eval "in_head != 0 || in_body != 0" {
            set "t.HTML_UNBALANCED_TAG" "1";
        }

        # Check for short HTML parts with a link to an image
        if eval "has_link_to_img" {
            if eval "html_char_count < 1024" {
                set "t.HTML_SHORT_LINK_IMG_1" "1";
            } elsif eval "html_char_count < 1536" {
                set "t.HTML_SHORT_LINK_IMG_2" "1";
            } elsif eval "html_char_count < 2048" {
                set "t.HTML_SHORT_LINK_IMG_3" "1";
            }
        } 
        
        if eval "(!has_link_to_img || html_char_count >= 2048) && 
                 (html_img_words / (html_words + html_img_words) > 0.5)" {
            # Message contains more images than text
            set "t.HTML_TEXT_IMG_RATIO" "1";
        }

        if eval "has_uri && !has_text" {
            set "t.BODY_URI_ONLY" "1";
        }
    }
}

