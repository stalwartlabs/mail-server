/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use ahash::AHashMap;
use common::{
    Server, auth::AccessToken, expr::functions::ResolveVariable, scripts::ScriptModification,
};

use mail_parser::Message;
use sieve::{Envelope, runtime::Variable};

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
    message: Option<Message<'x>>,
    headers: Option<&'x [u8]>,
    variables: AHashMap<Cow<'static, str>, Variable>,
    envelope: Vec<(Envelope, Variable)>,
    from_addr: String,
    from_name: String,
    return_path: String,
    sign: Vec<String>,
    access_token: Option<&'x AccessToken>,
    session_id: u64,
}

impl<'x> ScriptParameters<'x> {
    pub fn new() -> Self {
        ScriptParameters {
            variables: AHashMap::with_capacity(10),
            envelope: Vec::with_capacity(6),
            message: None,
            headers: None,
            from_addr: Default::default(),
            from_name: Default::default(),
            return_path: Default::default(),
            sign: Default::default(),
            access_token: None,
            session_id: Default::default(),
        }
    }

    pub async fn with_envelope(
        mut self,
        server: &Server,
        vars: &impl ResolveVariable,
        session_id: u64,
    ) -> Self {
        for (variable, expr) in [
            (&mut self.from_addr, &server.core.sieve.from_addr),
            (&mut self.from_name, &server.core.sieve.from_name),
            (&mut self.return_path, &server.core.sieve.return_path),
        ] {
            if let Some(value) = server.eval_if(expr, vars, session_id).await {
                *variable = value;
            }
        }
        if let Some(value) = server
            .eval_if(&server.core.sieve.sign, vars, session_id)
            .await
        {
            self.sign = value;
        }
        self
    }

    pub fn with_message(self, message: Message<'x>) -> Self {
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

    pub fn with_access_token(mut self, access_token: &'x AccessToken) -> Self {
        self.access_token = Some(access_token);
        self
    }

    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = session_id;
        self
    }
}

impl Default for ScriptParameters<'_> {
    fn default() -> Self {
        Self::new()
    }
}
