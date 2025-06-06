/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

pub fn locale_or_default(name: &str) -> &'static Locale {
    locale(name)
        .or_else(|| name.split_once('_').and_then(|(lang, _)| locale(lang)))
        .unwrap_or(&EN_LOCALES)
}
