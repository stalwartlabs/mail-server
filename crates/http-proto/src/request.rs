/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use http_body_util::BodyExt;

use crate::HttpRequest;

pub fn decode_path_element(item: &str) -> Cow<'_, str> {
    // Bit hackish but avoids an extra dependency
    form_urlencoded::parse(item.as_bytes())
        .into_iter()
        .next()
        .map(|(k, _)| k)
        .unwrap_or_else(|| item.into())
}

pub async fn fetch_body(
    req: &mut HttpRequest,
    max_size: usize,
    session_id: u64,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    while let Some(Ok(frame)) = req.frame().await {
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() <= max_size || max_size == 0 {
                bytes.extend_from_slice(data);
            } else {
                trc::event!(
                    Http(trc::HttpEvent::RequestBody),
                    SpanId = session_id,
                    Contents = std::str::from_utf8(&bytes)
                        .unwrap_or("[binary data]")
                        .to_string(),
                    Size = bytes.len(),
                    Limit = max_size,
                );

                return None;
            }
        }
    }

    trc::event!(
        Http(trc::HttpEvent::RequestBody),
        SpanId = session_id,
        Contents = std::str::from_utf8(&bytes)
            .unwrap_or("[binary data]")
            .to_string(),
        Size = bytes.len(),
    );

    bytes.into()
}
