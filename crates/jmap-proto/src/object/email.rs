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

use crate::{
    parser::{json::Parser, Ignore, JsonObjectParser},
    request::{RequestProperty, RequestPropertyParser},
    types::property::Property,
};

#[derive(Debug, Clone, Default)]
pub struct GetArguments {
    pub body_properties: Option<Vec<Property>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct QueryArguments {
    pub collapse_threads: Option<bool>,
}

impl RequestPropertyParser for GetArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match (&property.hash[0], &property.hash[1]) {
            (0x7365_6974_7265_706f_7250_7964_6f62, _) => {
                self.body_properties = <Option<Vec<Property>>>::parse(parser)?;
            }
            (0x6c61_5679_646f_4274_7865_5468_6374_6566, 0x0073_6575) => {
                self.fetch_text_body_values = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("fetchTextBodyValues")?;
            }
            (0x6c61_5679_646f_424c_4d54_4868_6374_6566, 0x0073_6575) => {
                self.fetch_html_body_values = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("fetchHTMLBodyValues")?;
            }
            (0x756c_6156_7964_6f42_6c6c_4168_6374_6566, 0x7365) => {
                self.fetch_all_body_values = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("fetchAllBodyValues")?;
            }
            (0x6574_7942_6575_6c61_5679_646f_4278_616d, 0x73) => {
                self.max_body_value_bytes = parser
                    .next_token::<Ignore>()?
                    .unwrap_usize_or_null("maxBodyValueBytes")?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}

impl RequestPropertyParser for QueryArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        if property.hash[0] == 0x0073_6461_6572_6854_6573_7061_6c6c_6f63 {
            self.collapse_threads = parser
                .next_token::<Ignore>()?
                .unwrap_bool_or_null("collapseThreads")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
