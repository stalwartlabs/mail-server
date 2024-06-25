/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
