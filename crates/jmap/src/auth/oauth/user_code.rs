/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header, StatusCode};
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use mail_send::mail_auth::common::lru::DnsCache;
use std::fmt::Write;
use store::rand::{distributions::Alphanumeric, thread_rng, Rng};

use crate::{
    api::{http::ToHttpResponse, HtmlResponse, HttpRequest, HttpResponse},
    JMAP,
};

use super::{
    parse_form_data, OAuthCode, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN, OAUTH_HTML_FOOTER,
    OAUTH_HTML_HEADER, OAUTH_HTML_LOGIN_CODE_HIDDEN, OAUTH_HTML_LOGIN_FORM,
    OAUTH_HTML_LOGIN_HEADER_CLIENT, OAUTH_HTML_LOGIN_HEADER_FAILED, STATUS_AUTHORIZED,
};

impl JMAP {
    // Code authorization flow, handles an authorization request
    pub async fn handle_user_code_auth(&self, req: &mut HttpRequest) -> HttpResponse {
        let params = form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect::<HashMap<_, _>>();
        let client_id = params
            .get("client_id")
            .map(|s| s.as_str())
            .unwrap_or_default();
        let redirect_uri = params
            .get("redirect_uri")
            .map(|s| s.as_str())
            .unwrap_or_default();

        // Validate clientId
        if client_id.len() > CLIENT_ID_MAX_LEN {
            return HtmlResponse::with_status(
                StatusCode::BAD_REQUEST,
                "Client ID is invalid.".to_string(),
            )
            .into_http_response();
        } else if !redirect_uri.starts_with("https://") {
            return HtmlResponse::with_status(
                StatusCode::BAD_REQUEST,
                "Redirect URI must be HTTPS".to_string(),
            )
            .into_http_response();
        }

        let mut cancel_link = format!("{}?error=access_denied", redirect_uri);
        if let Some(state) = params.get("state") {
            let _ = write!(cancel_link, "&state={}", state);
        }
        let code = String::from_utf8(
            base64_encode(&bincode::serialize(&(1u32, params)).unwrap_or_default())
                .unwrap_or_default(),
        )
        .unwrap();

        let mut response = String::with_capacity(
            OAUTH_HTML_HEADER.len()
                + OAUTH_HTML_LOGIN_HEADER_CLIENT.len()
                + OAUTH_HTML_LOGIN_CODE_HIDDEN.len()
                + OAUTH_HTML_LOGIN_FORM.len()
                + OAUTH_HTML_FOOTER.len()
                + code.len()
                + cancel_link.len()
                + 10,
        );

        response.push_str(&OAUTH_HTML_HEADER.replace("@@@", "/auth/code"));
        response.push_str(OAUTH_HTML_LOGIN_HEADER_CLIENT);
        response.push_str(&OAUTH_HTML_LOGIN_CODE_HIDDEN.replace("@@@", &code));
        response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", &cancel_link));
        response.push_str(OAUTH_HTML_FOOTER);

        HtmlResponse::new(response).into_http_response()
    }

    // Handles POST request from the code authorization form
    pub async fn handle_user_code_auth_post(&self, req: &mut HttpRequest) -> HttpResponse {
        // Parse form
        let params = match parse_form_data(req).await {
            Ok(params) => params,
            Err(err) => return err,
        };

        let mut auth_code = None;
        let (auth_attempts, code_req) = match params
            .get("code")
            .and_then(|code| base64_decode(code.as_bytes()))
            .and_then(|bytes| bincode::deserialize::<(u32, HashMap<String, String>)>(&bytes).ok())
        {
            Some(code) => code,
            None => {
                return HtmlResponse::with_status(
                    StatusCode::BAD_REQUEST,
                    "Failed to deserialize code.".to_string(),
                )
                .into_http_response();
            }
        };

        // Authenticate user
        if let (Some(email), Some(password)) = (params.get("email"), params.get("password")) {
            if let Some(access_token) = self.authenticate_plain(email, password).await {
                // Generate client code
                let client_code = thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(DEVICE_CODE_LEN)
                    .map(char::from)
                    .collect::<String>();

                // Add client code
                self.oauth_codes.insert(
                    client_code.clone(),
                    Arc::new(OAuthCode {
                        status: STATUS_AUTHORIZED.into(),
                        account_id: access_token.primary_id().into(),
                        client_id: code_req
                            .get("client_id")
                            .map(|s| s.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        redirect_uri: code_req.get("redirect_uri").cloned(),
                    }),
                    Instant::now() + Duration::from_secs(self.config.oauth_expiry_auth_code),
                );

                auth_code = client_code.into();
            }
        }

        // Build redirect link
        let mut redirect_link = if let Some(auth_code) = &auth_code {
            format!(
                "{}?code={}",
                code_req
                    .get("redirect_uri")
                    .map(|s| s.as_str())
                    .unwrap_or_default(),
                auth_code
            )
        } else {
            format!(
                "{}?error=access_denied",
                code_req
                    .get("redirect_uri")
                    .map(|s| s.as_str())
                    .unwrap_or_default()
            )
        };
        if let Some(state) = &code_req.get("state") {
            let _ = write!(redirect_link, "&state={}", state);
        }

        if auth_code.is_none() && (auth_attempts < self.config.oauth_max_auth_attempts) {
            let code = String::from_utf8(
                base64_encode(
                    &bincode::serialize(&(auth_attempts + 1, code_req)).unwrap_or_default(),
                )
                .unwrap_or_default(),
            )
            .unwrap();

            let mut response = String::with_capacity(
                OAUTH_HTML_HEADER.len()
                    + OAUTH_HTML_LOGIN_HEADER_CLIENT.len()
                    + OAUTH_HTML_LOGIN_CODE_HIDDEN.len()
                    + OAUTH_HTML_LOGIN_FORM.len()
                    + OAUTH_HTML_FOOTER.len()
                    + code.len()
                    + redirect_link.len()
                    + 10,
            );
            response.push_str(&OAUTH_HTML_HEADER.replace("@@@", "/auth/code"));
            response.push_str(OAUTH_HTML_LOGIN_HEADER_FAILED);
            response.push_str(&OAUTH_HTML_LOGIN_CODE_HIDDEN.replace("@@@", &code));
            response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", &redirect_link));
            response.push_str(OAUTH_HTML_FOOTER);

            HtmlResponse::new(response).into_http_response()
        } else {
            hyper::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, redirect_link)
                .body(
                    Full::new(Bytes::from(Vec::<u8>::new()))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap()
        }
    }
}
