/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
