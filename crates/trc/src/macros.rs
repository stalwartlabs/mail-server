/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Helper macro to count the number of arguments

#[macro_export]
macro_rules! event {
    ($event:ident($($param:expr),* $(,)?) $(, $key:ident = $value:expr)* $(,)?) => {
        {
            let et = $crate::EventType::$event($($param),*);
            let level = et.effective_level();
            if level.is_enabled() {
                $crate::Event::new(
                    et,
                    level,
                    trc::__count!($($key)*)
                )
                $(
                    .ctx($crate::Key::$key, $crate::Value::from($value))
                )*
                .send();
            }
        }
    };

    ($event:ident $(, $key:ident = $value:expr)* $(,)?) => {
        {
            let et = $crate::EventType::$event;
            let level = et.effective_level();
            if level.is_enabled() {
                $crate::Event::new(
                    et,
                    level,
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
