
# Message only has text/html MIME parts
if eval "header.content-type == 'text/html'" {
    let "t.MIME_HTML_ONLY" "1";
} 

foreverypart {
    if eval "eq_ignore_case(header.content-type, 'text/html')" {
        # Tokenize HTML
        let "is_body_part" "is_body()";
        let "html_tokens" "tokenize(part.text, 'html')";
        let "html_tokens_len" "len(html_tokens)";
        let "html_char_count" "0";
        let "html_space_count" "0";
        let "html_img_words" "0";
        let "html_words" "0";
        let "has_link_to_img" "0";
        let "has_uri" "0";
        let "has_text" "0";
        let "in_head" "0";
        let "in_body" "0";
        let "in_anchor" "0";
        let "in_anchor_href_ip" "0";
        let "in_anchor_href" "";

        let "i" "0";
        while "i < html_tokens_len" {
            let "token" "html_tokens[i]";
            let "i" "i + 1";

            # Tokens starting with '_' are text nodes
            if eval "starts_with(token, '_')" {
                if eval "in_head == 0" {
                    let "html_char_count" "html_char_count + count_chars(token)";
                    let "html_space_count" "html_space_count + count_spaces(token)";

                    let "text" "to_lowercase(trim(strip_prefix(token, '_')))";
                    let "html_words" "html_words + len(tokenize(text, 'words'))";

                    let "uris" "tokenize(text, 'uri')";

                    if eval "!is_empty(uris)" {
                        let "has_uri" "1";
                        let "uri" "uris[0]";

                        if eval "in_anchor && !is_empty(in_anchor_href)" {
                            if eval "contains(text, '://') &&
                                    uri_part(uri, 'scheme') != uri_part(in_anchor_href, 'scheme')" {
                                # The anchor text contains a distinct scheme compared to the target URL
                                let "t.HTTP_TO_HTTPS" "1";
                            }
                            if eval "(!in_anchor_href_ip && (domain_part(uri_part(uri, 'host'), 'sld') != domain_part(uri_part(in_anchor_href, 'host'), 'sld'))) ||
                                     (in_anchor_href_ip && (uri_part(uri, 'host') != uri_part(in_anchor_href, 'host')))" {
                                let "t.PHISHING" "1";
                            }
                        }
                    } elsif eval "!is_empty(text)" {
                        let "has_text" "1";
                    }
                }
            } elsif eval "starts_with(token, '<img')" {
                if eval "is_body_part" {
                    let "dimensions" "html_attr_size(token, 'width', 800) + html_attr_size(token, 'height', 600)";

                    if eval "in_anchor && dimensions >= 210" {
                        let "has_link_to_img" "1";
                    }
                    if eval "dimensions > 100" {
                        # We assume that a single picture 100x200 contains approx 3 words of text
                        let "html_img_words" "html_img_words + dimensions / 100";
                    }

                    let "img_src" "html_attr(token, 'src')";
                    if eval "starts_with(img_src, 'data:') && contains(img_src, ';base64,')" {
                        # Has Data URI encoding
                        let "t.HAS_DATA_URI" "1";
                    }
                }
            } elsif eval "starts_with(token, '<head')" {
                let "in_head" "in_head + 1";
            } elsif eval "starts_with(token, '</head')" {
                let "in_head" "in_head - 1";
            } elsif eval "starts_with(token, '<body')" {
                let "in_body" "in_body + 1";
            } elsif eval "starts_with(token, '</body')" {
                let "in_body" "in_body - 1";
            } elsif eval "starts_with(token, '<a ')" {
                let "in_anchor" "1";
                let "in_anchor_href_ip" "0";
                let "in_anchor_href" "to_lowercase(trim(html_attr(token, 'href')))";

                if eval "is_body_part && starts_with(in_anchor_href, 'data:') && contains(in_anchor_href, ';base64,')" {
                    # Has Data URI encoding
                    let "t.HAS_DATA_URI" "1";
                    if eval "contains(in_anchor_href, 'text/')" {
                        # Uses Data URI encoding to obfuscate plain or HTML in base64
                        let "t.DATA_URI_OBFU" "1";
                    }
                } elsif eval "is_ip_addr(uri_part(in_anchor_href, 'host'))" {
                    # HTML anchor points to an IP address
                    let "t.HTTP_TO_IP" "1";
                    let "in_anchor_href_ip" "1";
                }
            } elsif eval "in_anchor && starts_with(token, '</a')" {
                let "in_anchor" "0";
            } elsif eval "starts_with(token, '<meta ')" {
                if eval "eq_ignore_case(html_attr(token, 'http-equiv'), 'refresh') &&
                         contains_ignore_case(html_attr(token, 'content'), 'url=')" {
                    # HTML meta refresh tag
                    let "t.HTML_META_REFRESH_URL" "1";
                }
            } elsif eval "starts_with(token, '<link') && is_body_part &&
                            (contains_ignore_case(html_attr(token, 'rel'), 'stylesheet') ||
                             contains_ignore_case(html_attr(token, 'href'), '.css') )" {
                let "t.EXT_CSS" "1";
            }
        }

        if eval "is_body_part" {
            # Check for unbalanced tags
            if eval "in_head != 0 || in_body != 0" {
                let "t.HTML_UNBALANCED_TAG" "1";
            }

            # Check for short HTML parts with a link to an image
            if eval "has_link_to_img" {
                if eval "html_char_count < 1024" {
                    let "t.HTML_SHORT_LINK_IMG_1" "1";
                } elsif eval "html_char_count < 1536" {
                    let "t.HTML_SHORT_LINK_IMG_2" "1";
                } elsif eval "html_char_count < 2048" {
                    let "t.HTML_SHORT_LINK_IMG_3" "1";
                }
            } 
            
            if eval "(!has_link_to_img || html_char_count >= 2048) && 
                    (html_img_words / (html_words + html_img_words) > 0.5)" {
                # Message contains more images than text
                let "t.HTML_TEXT_IMG_RATIO" "1";
            }

            if eval "has_uri && !has_text" {
                let "t.BODY_URI_ONLY" "1";
            }
        }
    }
}

