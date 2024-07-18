/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[macro_export]
macro_rules! trace {
     ($event:ident $(, $key:ident = $value:expr)* $(,)?) => {
         {
             let event = $crate::Trace::new($crate::Event::$event)
             $(
                 .ctx($crate::Key::$key, $crate::Value::from($value))
             )* ;

             //eprintln!("{}", event);
         }
     };
 }

#[macro_export]
macro_rules! error {
    ($cause:ident $(, $key:ident = $value:expr)* $(,)?) => {{
        let event = $crate::Trace::new($crate::Event::Error($crate::Cause::$cause))
        .ctx($crate::Key::CausedBy, $crate::location!())
        $(
            .ctx($crate::Key::$key, $crate::Value::from($value))
        )* ;

        //eprintln!("{}", event);
    }};
}

#[macro_export]
macro_rules! location {
    () => {{
        concat!(file!(), ":", line!(), " (", module_path!(), ")")
    }};
}

#[macro_export]
macro_rules! bail {
    ($err:expr $(,)?) => {
        return Err($err);
    };
}
