/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{borrow::Cow, sync::Arc};

use ahash::AHashMap;
use sieve::{runtime::Variable, Envelope};

pub mod envelope;
pub mod event_loop;
pub mod exec;
pub mod plugins;

#[derive(Debug)]
pub enum ScriptResult {
    Accept {
        modifications: Vec<(Envelope, String)>,
    },
    Replace {
        message: Vec<u8>,
        modifications: Vec<(Envelope, String)>,
    },
    Reject(String),
    Discard,
}

pub struct ScriptParameters {
    message: Option<Arc<Vec<u8>>>,
    variables: AHashMap<Cow<'static, str>, Variable<'static>>,
    envelope: Vec<(Envelope, Variable<'static>)>,
}

impl ScriptParameters {
    pub fn new() -> Self {
        ScriptParameters {
            variables: AHashMap::with_capacity(10),
            envelope: Vec::with_capacity(6),
            message: None,
        }
    }

    pub fn with_message(self, message: Arc<Vec<u8>>) -> Self {
        Self {
            message: message.into(),
            ..self
        }
    }

    pub fn set_variable(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'static>>,
    ) -> Self {
        self.variables.insert(name.into(), value.into());
        self
    }
}

impl Default for ScriptParameters {
    fn default() -> Self {
        Self::new()
    }
}
