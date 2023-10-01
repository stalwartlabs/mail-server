if eval "!header.mime-version.exists" {
    if eval "header.content-type.exists || header.content-transfer-encoding.exists" {
        let "t.MISSING_MIME_VERSION" "1";
    }
} elsif eval "header.mime-version.raw_name != 'MIME-Version'" {
    let "t.MV_CASE" "1";
}

let "has_text_part" "0";
let "is_encrypted" "0";

foreverypart {
    let "type" "to_lowercase(header.content-type.type)";
    let "subtype" "to_lowercase(header.content-type.subtype)";
    let "cte" "header.content-transfer-encoding";
    let "part_is_attachment" "is_attachment()";

    if eval "cte != '' && !is_lowercase(cte)" {
        let "cte" "to_lowercase(cte)";
        let "t.CTE_CASE" "1";
    }

    if eval "ends_with(header.content-type.raw, ';')" {
        # Content-Type header ends with a semi-colon
        let "t.CT_EXTRA_SEMI" "1";
    }

    if eval "type == 'multipart'" {
        if eval "subtype == 'alternative'" {
            let "has_plain_part" "0";
            let "has_html_part" "0";
            
            let "text_part_words" "";
            let "text_part_uris" "0";

            let "html_part_words" "";
            let "html_part_uris" "0";

            foreverypart {
                let "ma_ct" "to_lowercase(header.content-type)";

                if eval "!has_plain_part && ma_ct == 'text/plain'" {
                    let "text_part" "part.text";
                    let "text_part_words" "tokenize_words(text_part)";
                    let "text_part_uris" "count(tokenize_url(text_part, true))";
                    let "has_plain_part" "1";
                } elsif eval "!has_html_part && ma_ct == 'text/html'" {
                    let "html_part" "html_to_text(part.text)";
                    let "html_part_words" "tokenize_words(html_part)";
                    let "html_part_uris" "count(tokenize_url(html_part, true))";
                    let "has_html_part" "1";
                }
            }

            # Multipart message mostly text/html MIME
            if eval "has_html_part" {
                if eval "!has_plain_part" {
                    let "t.MIME_MA_MISSING_TEXT" "1";
                } 
            } elsif eval "has_plain_part" {
                let "t.MIME_MA_MISSING_HTML" "1";
            }

            # HTML and text parts are different
            if eval "!t.R_PARTS_DIFFER && has_html_part && has_plain_part &&
                     (!is_empty(text_part_words) || !is_empty(html_part_words)) &&
                     cosine_similarity(text_part_words, html_part_words) < 0.95" {
                let "t.R_PARTS_DIFFER" "1";
            }

            # Odd URI count between parts
            if eval "text_part_uris != html_part_uris" {
                set "t.URI_COUNT_ODD" "1";
            }
        } elsif eval "subtype == 'mixed'" {
            let "num_text_parts" "0";
            let "has_other_part" "0";

            foreverypart {
                if eval "eq_ignore_case(header.content-type.type, 'text') && !is_attachment()" {
                    let "num_text_parts" "num_text_parts + 1";
                } elsif eval "!eq_ignore_case(header.content-type.type, 'multipart')" {
                    let "has_other_part" "1";
                }
            }
            
            # Found multipart/mixed without non-textual part
            if eval "!has_other_part && num_text_parts < 3" {
                let "t.CTYPE_MIXED_BOGUS" "1";
            }
        } elsif eval "subtype == 'encrypted'" {
            set "is_encrypted" "1";
        }
    } elsif eval "type == 'text'" {
        # MIME text part claims to be ASCII but isn't
        if eval "cte == '' || cte == '7bit'" {
            if eval "!is_ascii(part.raw)" {
                let "t.R_BAD_CTE_7BIT" "1";
            }
        } else {
            if eval "cte == 'base64'" {
                # Has text part encoded in base64
                let "t.MIME_BASE64_TEXT" "1";
                if eval "is_ascii(part.text)" {
                    # Has text part encoded in base64 that does not contain any 8bit characters
                    let "t.MIME_BASE64_TEXT_BOGUS" "1";
                }
            }

            if eval "subtype == 'plain' && is_empty(header.content-type.attr.charset)" {
                # Charset header is missing
                let "t.R_MISSING_CHARSET" "1";
            }
        }
        let "has_text_part" "1";
    } elsif eval "type == 'application'" {
        if eval "subtype == 'pkcs7-mime'" {
            let "t.ENCRYPTED_SMIME" "1";
            let "part_is_attachment" "0";
        } elsif eval "subtype == 'pkcs7-signature'" {
            let "t.SIGNED_SMIME" "1";
            let "part_is_attachment" "0";
        } elsif eval "subtype == 'pgp-encrypted'" {
            let "t.ENCRYPTED_PGP" "1";
            let "part_is_attachment" "0";
        } elsif eval "subtype == 'pgp-signature'" {
            let "t.SIGNED_PGP" "1";
            let "part_is_attachment" "0";
        } elsif eval "subtype == 'octet-stream'" {
            if eval "!is_encrypted &&
                     !header.content-id.exists && 
                     (!header.content-disposition.exists || 
                      (!eq_ignore_case(header.content-disposition.type, 'attachment') && 
                       is_empty(header.content-disposition.attr.filename)))" {
                let "t.CTYPE_MISSING_DISPOSITION" "1";
            }
        }
    }

    if eval "is_empty(type)" {
        if eval "header.content-type.exists" {
            let "t.BROKEN_CONTENT_TYPE" "1";
        }
    } elsif eval "!header.Content-Disposition:Content-Transfer-Encoding:MIME-Version.exists && (type != 'text' || subtype != 'plain')" {
        # Only Content-Type header without other MIME headers
        let "t.MIME_HEADER_CTYPE_ONLY" "1";
    }

    if eval "part_is_attachment" {
        # Has a MIME attachment
        let "t.HAS_ATTACHMENT" "1";
    }
}

if eval "has_text_part && (t.ENCRYPTED_SMIME || t.SIGNED_SMIME || t.ENCRYPTED_PGP || t.SIGNED_PGP)" {
    let "t.BOGUS_ENCRYPTED_AND_TEXT" "1";
}
