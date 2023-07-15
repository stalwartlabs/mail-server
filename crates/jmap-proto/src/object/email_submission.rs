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

use utils::map::vec_map::VecMap;

use crate::{
    parser::{json::Parser, JsonObjectParser},
    request::{reference::MaybeReference, RequestProperty, RequestPropertyParser},
    types::{id::Id, value::SetValue},
};

use super::Object;

#[derive(Debug, Clone, Default)]
pub struct SetArguments {
    pub on_success_update_email: Option<VecMap<MaybeReference<Id, String>, Object<SetValue>>>,
    pub on_success_destroy_email: Option<Vec<MaybeReference<Id, String>>>,
}

impl RequestPropertyParser for SetArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        if property.hash[0] == 0x4565_7461_6470_5573_7365_6363_7553_6e6f
            && property.hash[1] == 0x6c69_616d
        {
            self.on_success_update_email =
                <Option<VecMap<MaybeReference<Id, String>, Object<SetValue>>>>::parse(parser)?;
            Ok(true)
        } else if property.hash[0] == 0x796f_7274_7365_4473_7365_6363_7553_6e6f
            && property.hash[1] == 0x006c_6961_6d45
        {
            self.on_success_destroy_email =
                <Option<Vec<MaybeReference<Id, String>>>>::parse(parser)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
