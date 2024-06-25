/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::panic;

use lopdf::Document;

pub fn extract_pdf(bytes: &[u8]) -> Option<String> {
    panic::catch_unwind(|| {
        let mut buf = Vec::<u8>::new();
        let mut out = PlainTextOutput::new(&mut buf as &mut dyn std::io::Write);

        output_doc(&Document::load_mem(bytes).ok()?, &mut out).ok()?;

        match String::from_utf8(buf) {
            Ok(result) => result,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        }
        .into()
    })
    .ok()?
}

/*
#[cfg(test)]
mod tests {

    #[test]
    fn extract_pdf() {
        let bytes = include_bytes!("/tmp/pdf/files/ep.pdf");
        let text = super::extract_pdf(bytes);
    }
}
*/
