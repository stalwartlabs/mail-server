/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[macro_export]
macro_rules! event {
    ($event:ident($($param:expr),* $(,)?) $(, $key:ident = $value:expr)* $(,)?) => {
        {
            const ET : $crate::EventType = $crate::EventType::$event($($param),*);
            const ET_ID : usize = ET.id();
            if $crate::collector::Collector::has_interest(ET_ID) {
                $crate::Event::with_capacity(
                    ET,
                    trc::__count!($($key)*)
                )
                $(
                    .ctx($crate::Key::$key, $crate::Value::from($value))
                )*
                .send();
            }
        }
    };
}

#[macro_export]
macro_rules! eventd {
    ($event:ident($($param:expr),* $(,)?) $(, $key:ident = $value:expr)* $(,)?) => {
        {
            let et = $crate::EventType::$event($($param),*);
            if $crate::collector::Collector::has_interest(et) {
                $crate::Event::with_capacity(
                    et,
                    trc::__count!($($key)*)
                )
                $(
                    .ctx($crate::Key::$key, $crate::Value::from($value))
                )*
                .send();
            }
        }
    };
}

#[macro_export]
macro_rules! __count {
    () => (0usize);
    ($head:tt $($tail:tt)*) => (1usize + trc::__count!($($tail)*));
}

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

        if $crate::collector::Collector::has_interest(err.as_ref().id()) {
            err.send();
        }
    };
}
