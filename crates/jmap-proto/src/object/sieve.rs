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
    parser::json::Parser,
    request::{reference::MaybeReference, RequestProperty, RequestPropertyParser},
    types::id::Id,
};

#[derive(Debug, Clone, Default)]
pub struct SetArguments {
    pub on_success_activate_script: Option<MaybeReference<Id, String>>,
    pub on_success_deactivate_script: Option<bool>,
}

impl RequestPropertyParser for SetArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        if property.hash[0] == 0x7461_7669_7463_4173_7365_6363_7553_6e6f
            && property.hash[1] == 0x0074_7069_7263_5365
        {
            self.on_success_activate_script = parser
                .next_token::<MaybeReference<Id, String>>()?
                .unwrap_string_or_null("onSuccessActivateScript")?;
            Ok(true)
        } else if property.hash[0] == 0x7669_7463_6165_4473_7365_6363_7553_6e6f
            && property.hash[1] == 0x0074_7069_7263_5365_7461
        {
            self.on_success_deactivate_script = parser
                .next_token::<bool>()?
                .unwrap_bool_or_null("onSuccessDeactivateScript")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
