/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use ahash::AHashSet;
use utils::config::Config;

use crate::lookup::Lookup;

use super::ConfigContext;

pub trait ConfigList {
    fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()>;
    fn parse_list(&self, id: &str) -> super::Result<Lookup>;
}

impl ConfigList for Config {
    fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("list") {
            ctx.lookup
                .insert(format!("list/{id}"), Arc::new(self.parse_list(id)?));
        }

        Ok(())
    }

    fn parse_list(&self, id: &str) -> super::Result<Lookup> {
        let mut entries = AHashSet::new();
        for (_, value) in self.values(("list", id)) {
            if let Some(path) = value.strip_prefix("file://") {
                for line in BufReader::new(File::open(path).map_err(|err| {
                    format!("Failed to read file {path:?} for list {id:?}: {err}")
                })?)
                .lines()
                {
                    let line_ = line.map_err(|err| {
                        format!("Failed to read file {path:?} for list {id:?}: {err}")
                    })?;
                    let line = line_.trim();
                    if !line.is_empty() {
                        entries.insert(line.to_string());
                    }
                }
            } else {
                entries.insert(value.to_string());
            }
        }
        Ok(Lookup::Local(entries))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::{AHashMap, AHashSet};
    use utils::config::Config;

    use crate::{
        config::{remote::ConfigHost, ConfigContext},
        lookup::Lookup,
    };

    use super::ConfigList;

    #[test]
    fn parse_lists() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("smtp");
        file.push("config");
        file.push("lists.toml");

        let mut list_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        list_path.push("resources");
        list_path.push("smtp");
        list_path.push("lists");
        let mut list1 = list_path.clone();
        list1.push("test-list1.txt");
        let mut list2 = list_path.clone();
        list2.push("test-list2.txt");

        let toml = fs::read_to_string(file)
            .unwrap()
            .replace("{LIST1}", list1.as_path().to_str().unwrap())
            .replace("{LIST2}", list2.as_path().to_str().unwrap());

        let config = Config::parse(&toml).unwrap();
        let mut context = ConfigContext::default();
        config.parse_remote_hosts(&mut context).unwrap();
        config.parse_lists(&mut context).unwrap();

        let mut expected_lists = AHashMap::from_iter([
            (
                "list/local-domains".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "example.org".to_string(),
                    "example.net".to_string(),
                ]))),
            ),
            (
                "list/spammer-domains".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "thatdomain.net".to_string()
                ]))),
            ),
            (
                "list/local-users".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                ]))),
            ),
            (
                "list/power-users".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                    "user3@example.net".to_string(),
                    "user4@example.net".to_string(),
                    "user5@example.net".to_string(),
                ]))),
            ),
            (
                "remote/lmtp".to_string(),
                context.lookup.get("remote/lmtp").unwrap().clone(),
            ),
        ]);

        for (key, list) in context.lookup {
            assert_eq!(Some(list), expected_lists.remove(&key), "failed for {key}");
        }
    }
}
