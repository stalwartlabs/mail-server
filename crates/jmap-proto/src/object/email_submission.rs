/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
