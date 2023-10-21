if eval "!header.mime-version.exists" {
    if eval "header.content-type.exists || header.content-transfer-encoding.exists" {
        let "t.MISSING_MIME_VERSION" "1";
    }
} elsif eval "header.mime-version.raw_name != 'MIME-Version'" {
    let "t.MV_CASE" "1";
}

let "has_text_part" "0";
let "is_encrypted" "0";

if eval "header.Content-Type.exists && !header.Content-Disposition:Content-Transfer-Encoding:MIME-Version.exists && !eq_ignore_case(header.Content-Type, 'text/plain')" {
    # Only Content-Type header without other MIME headers
    let "t.MIME_HEADER_CTYPE_ONLY" "1";
}

foreverypart {
    let "content_type" "to_lowercase(header.content-type)";
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
                    let "text_part_words" "tokenize(text_part, 'words')";
                    let "text_part_uris" "count(tokenize(text_part, 'uri_strict'))";
                    let "has_plain_part" "1";
                } elsif eval "!has_html_part && ma_ct == 'text/html'" {
                    let "html_part" "html_to_text(part.text)";
                    let "html_part_words" "tokenize(html_part, 'words')";
                    let "html_part_uris" "count(tokenize(html_part, 'uri_strict'))";
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
                if eval "is_ascii(part.text)" {
                    # Has text part encoded in base64 that does not contain any 8bit characters
                    let "t.MIME_BASE64_TEXT_BOGUS" "1";
                } else {
                    # Has text part encoded in base64
                    let "t.MIME_BASE64_TEXT" "1";
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

    if eval "is_empty(type) && header.content-type.exists" {
        let "t.BROKEN_CONTENT_TYPE" "1";
    }

    if eval "part_is_attachment" {
        # Has a MIME attachment
        let "t.HAS_ATTACHMENT" "1";

        # Detect and compare mime type
        let "detected_mime_type" "detect_file_type('mime')";
        if eval "!is_empty(detected_mime_type)" {
            if eval "detected_mime_type == content_type" {
                # Known content-type
                let "t.MIME_GOOD" "1";
            } elsif eval "content_type != 'application/octet-stream'" {
                # Known bad content-type
                let "t.MIME_BAD" "1";
            }
        }
    }

    # Analyze attachment name
    let "attach_name" "attachment_name()";
    if eval "!is_empty(attach_name)" {
        if eval "has_obscured(attach_name)" {
            let "t.MIME_BAD_UNICODE" "1";
        }
        let "name_parts" "rsplit(to_lowercase(attach_name), '.')";
        if eval "count(name_parts) > 1" {
            let "ext_type" "lookup_map('spam/mime-types', name_parts[0])";
            if eval "!is_empty(ext_type)" {
                let "ext_type_double" "lookup_map('spam/mime-types', name_parts[1])";
                if eval "contains(ext_type, 'BAD')" {
                    # Bad extension
                    if eval "contains(ext_type_double, 'BAD')" {
                        let "t.MIME_DOUBLE_BAD_EXTENSION" "1";
                    } else {
                        let "t.MIME_BAD_EXTENSION" "1";
                    }
                }
                if eval "contains(ext_type, 'AR') && contains(ext_type_double, 'AR')" {
                    # Archive in archive
                    let "t.MIME_ARCHIVE_IN_ARCHIVE" "1";
                }

                if eval "contains(ext_type, '/') && 
                            content_type != 'application/octet-stream' && 
                            !contains(split(ext_type, '|'), content_type)" {
                    # Invalid attachment mime type
                    let "t.MIME_BAD_ATTACHMENT" "1";
                }
            }
        }
    }

}

if eval "has_text_part && (t.ENCRYPTED_SMIME || t.SIGNED_SMIME || t.ENCRYPTED_PGP || t.SIGNED_PGP)" {
    let "t.BOGUS_ENCRYPTED_AND_TEXT" "1";
}

# Check for mixed script in body
if eval "!is_single_script(text_body)" {
    let "t.R_MIXED_CHARSET" "1";
}
