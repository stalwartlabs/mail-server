/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use crate::{
    parser::{json::Parser, Ignore},
    request::{RequestProperty, RequestPropertyParser},
};

#[derive(Debug, Clone, Default)]
pub struct SetArguments {
    pub on_destroy_remove_emails: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct QueryArguments {
    pub sort_as_tree: Option<bool>,
    pub filter_as_tree: Option<bool>,
}

impl RequestPropertyParser for SetArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        if property.hash[0] == 0x4565_766f_6d65_5279_6f72_7473_6544_6e6f
            && property.hash[1] == 0x0073_6c69_616d
        {
            self.on_destroy_remove_emails = parser
                .next_token::<Ignore>()?
                .unwrap_bool_or_null("onDestroyRemoveEmails")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl RequestPropertyParser for QueryArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match &property.hash[0] {
            0x6565_7254_7341_7472_6f73 => {
                self.sort_as_tree = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("sortAsTree")?;
            }
            0x6565_7254_7341_7265_746c_6966 => {
                self.filter_as_tree = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("filterAsTree")?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}
