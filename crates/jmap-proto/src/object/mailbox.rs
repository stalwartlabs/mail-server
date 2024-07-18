/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
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
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
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
