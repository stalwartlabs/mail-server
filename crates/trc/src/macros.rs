/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[macro_export]
macro_rules! location {
    () => {{
        concat!(file!(), ":", line!())
    }};
}

#[macro_export]
macro_rules! bail {
    ($err:expr $(,)?) => {
        return Err($err);
    };
}

#[macro_export]
macro_rules! error {
    ($err:expr $(,)?) => {
        let err = $err;
        let event_id = err.as_ref().id();

        if $crate::collector::Collector::has_interest(event_id)
            || $crate::collector::Collector::is_metric(event_id)
        {
            err.send();
        }
    };
}
