/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use dav_proto::schema::response::Href;
use percent_encoding::NON_ALPHANUMERIC;

use crate::DavResourceName;

pub mod matching;
pub mod propfind;
pub mod propsearch;

pub trait CurrentUserPrincipal {
    fn current_user_principal(&self) -> Href;
}

impl CurrentUserPrincipal for AccessToken {
    fn current_user_principal(&self) -> Href {
        Href(format!(
            "{}/{}/",
            DavResourceName::Principal.base_path(),
            percent_encoding::utf8_percent_encode(&self.name, NON_ALPHANUMERIC)
        ))
    }
}
