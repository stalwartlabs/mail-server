/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use ahash::AHashSet;

#[derive(Debug, Clone, Default)]
pub struct PublicSuffix {
    pub suffixes: AHashSet<String>,
    pub exceptions: AHashSet<String>,
    pub wildcards: Vec<String>,
}

impl PublicSuffix {
    pub fn contains(&self, suffix: &str) -> bool {
        self.suffixes.contains(suffix)
            || (!self.exceptions.contains(suffix)
                && self.wildcards.iter().any(|w| suffix.ends_with(w)))
    }
}

impl From<&str> for PublicSuffix {
    fn from(list: &str) -> Self {
        let mut ps = PublicSuffix::default();
        for line in list.lines() {
            let line = line.trim().to_lowercase();
            if !line.starts_with("//") {
                if let Some(domain) = line.strip_prefix('*') {
                    ps.wildcards.push(domain.to_string());
                } else if let Some(domain) = line.strip_prefix('!') {
                    ps.exceptions.insert(domain.to_string());
                } else {
                    ps.suffixes.insert(line.to_string());
                }
            }
        }
        ps.suffixes.insert("onion".to_string());
        ps
    }
}
