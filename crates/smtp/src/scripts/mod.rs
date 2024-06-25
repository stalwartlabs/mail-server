/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use ahash::AHashMap;
use common::{expr::functions::ResolveVariable, scripts::ScriptModification, Core};
use sieve::{runtime::Variable, Envelope};

pub mod envelope;
pub mod event_loop;
pub mod exec;

#[derive(Debug, serde::Serialize)]
pub enum ScriptResult {
    Accept {
        modifications: Vec<ScriptModification>,
    },
    Replace {
        message: Vec<u8>,
        modifications: Vec<ScriptModification>,
    },
    Reject(String),
    Discard,
}

pub struct ScriptParameters<'x> {
    message: Option<&'x [u8]>,
    headers: Option<&'x [u8]>,
    variables: AHashMap<Cow<'static, str>, Variable>,
    envelope: Vec<(Envelope, Variable)>,
    from_addr: String,
    from_name: String,
    return_path: String,
    sign: Vec<String>,
    #[cfg(feature = "test_mode")]
    expected_variables: Option<AHashMap<String, Variable>>,
}

impl<'x> ScriptParameters<'x> {
    pub fn new() -> Self {
        ScriptParameters {
            variables: AHashMap::with_capacity(10),
            envelope: Vec::with_capacity(6),
            message: None,
            headers: None,
            #[cfg(feature = "test_mode")]
            expected_variables: None,
            from_addr: Default::default(),
            from_name: Default::default(),
            return_path: Default::default(),
            sign: Default::default(),
        }
    }

    pub async fn with_envelope(mut self, core: &Core, vars: &impl ResolveVariable) -> Self {
        for (variable, expr) in [
            (&mut self.from_addr, &core.sieve.from_addr),
            (&mut self.from_name, &core.sieve.from_name),
            (&mut self.return_path, &core.sieve.return_path),
        ] {
            if let Some(value) = core.eval_if(expr, vars).await {
                *variable = value;
            }
        }
        if let Some(value) = core.eval_if(&core.sieve.sign, vars).await {
            self.sign = value;
        }
        self
    }

    pub fn with_message(self, message: &'x [u8]) -> Self {
        Self {
            message: message.into(),
            ..self
        }
    }

    pub fn with_auth_headers(self, headers: &'x [u8]) -> Self {
        Self {
            headers: headers.into(),
            ..self
        }
    }

    pub fn set_variable(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable>,
    ) -> Self {
        self.variables.insert(name.into(), value.into());
        self
    }

    pub fn set_envelope(mut self, envelope: Envelope, value: impl Into<Variable>) -> Self {
        self.envelope.push((envelope, value.into()));
        self
    }

    #[cfg(feature = "test_mode")]
    pub fn with_expected_variables(
        mut self,
        expected_variables: AHashMap<String, Variable>,
    ) -> Self {
        self.expected_variables = expected_variables.into();
        self
    }
}

impl Default for ScriptParameters<'_> {
    fn default() -> Self {
        Self::new()
    }
}
