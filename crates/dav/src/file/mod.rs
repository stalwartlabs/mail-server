/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 pub mod acl;
pub mod changes;
pub mod copy_move;
pub mod delete;
pub mod get;
pub mod lock;
pub mod mkcol;
pub mod propfind;
pub mod proppatch;
pub mod update;

pub(crate) enum UpdateType {
    Post(Vec<u8>),
    Put(Vec<u8>),
    Patch(Vec<u8>),
}
