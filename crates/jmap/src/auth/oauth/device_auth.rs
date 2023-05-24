use std::{
    sync::{atomic, Arc},
    time::{Duration, Instant},
};

use hyper::StatusCode;
use mail_send::mail_auth::common::lru::DnsCache;
use store::rand::{
    distributions::{Alphanumeric, Standard},
    thread_rng, Rng,
};
use utils::listener::ServerInstance;

use crate::{
    api::{http::ToHttpResponse, HtmlResponse, HttpRequest, HttpResponse, JsonResponse},
    auth::oauth::{
        OAUTH_HTML_ERROR, OAUTH_HTML_LOGIN_HEADER_FAILED, OAUTH_HTML_LOGIN_SUCCESS,
        STATUS_AUTHORIZED,
    },
    JMAP,
};

use super::{
    parse_form_data, DeviceAuthResponse, OAuthCode, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN,
    OAUTH_HTML_FOOTER, OAUTH_HTML_HEADER, OAUTH_HTML_LOGIN_CODE, OAUTH_HTML_LOGIN_FORM,
    OAUTH_HTML_LOGIN_HEADER_DEVICE, STATUS_PENDING, USER_CODE_ALPHABET, USER_CODE_LEN,
};

// Device authorization endpoint
impl JMAP {
    pub async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        instance: Arc<ServerInstance>,
    ) -> HttpResponse {
        // Parse form
        let client_id = match parse_form_data(req)
            .await
            .map(|mut p| p.remove("client_id"))
        {
            Ok(Some(client_id)) if client_id.len() < CLIENT_ID_MAX_LEN => client_id,
            Err(err) => return err,
            _ => {
                return HtmlResponse::with_status(
                    StatusCode::BAD_REQUEST,
                    "Client ID is invalid.".to_string(),
                )
                .into_http_response();
            }
        };

        // Generate device code
        let device_code = thread_rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();

        // Generate user code
        let mut user_code = String::with_capacity(USER_CODE_LEN + 1);
        for (pos, ch) in thread_rng()
            .sample_iter::<usize, _>(Standard)
            .take(USER_CODE_LEN)
            .map(|v| char::from(USER_CODE_ALPHABET[v % USER_CODE_ALPHABET.len()]))
            .enumerate()
        {
            if pos == USER_CODE_LEN / 2 {
                user_code.push('-');
            }
            user_code.push(ch);
        }

        // Add OAuth status
        let oauth_code = Arc::new(OAuthCode {
            status: STATUS_PENDING.into(),
            account_id: u32::MAX.into(),
            client_id,
            redirect_uri: None,
        });
        let expiry = Instant::now() + Duration::from_secs(self.config.oauth_expiry_user_code);
        self.oauth_codes
            .insert(device_code.clone(), oauth_code.clone(), expiry);
        self.oauth_codes
            .insert(user_code.clone(), oauth_code, expiry);

        // Build response
        JsonResponse::new(DeviceAuthResponse {
            verification_uri: format!("{}/auth", instance.data),
            verification_uri_complete: format!("{}/auth/code?={}", instance.data, user_code),
            device_code,
            user_code,
            expires_in: self.config.oauth_expiry_user_code,
            interval: 5,
        })
        .into_http_response()
    }

    // Device authorization flow, renders the authorization page
    pub async fn handle_user_device_auth(&self, req: &mut HttpRequest) -> HttpResponse {
        let code = req
            .uri()
            .query()
            .and_then(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned())
            })
            .unwrap_or_default();
        let mut response = String::with_capacity(
            OAUTH_HTML_HEADER.len()
                + OAUTH_HTML_LOGIN_HEADER_DEVICE.len()
                + OAUTH_HTML_LOGIN_CODE.len()
                + OAUTH_HTML_LOGIN_FORM.len()
                + OAUTH_HTML_FOOTER.len()
                + code.len()
                + 16,
        );

        response.push_str(&OAUTH_HTML_HEADER.replace("@@@", "/auth"));
        response.push_str(OAUTH_HTML_LOGIN_HEADER_DEVICE);
        response.push_str(&OAUTH_HTML_LOGIN_CODE.replace("@@@", &code));
        response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", "about:blank"));
        response.push_str(OAUTH_HTML_FOOTER);

        HtmlResponse::new(response).into_http_response()
    }

    // Handles POST request from the device authorization form
    pub async fn handle_user_device_auth_post(&self, req: &mut HttpRequest) -> HttpResponse {
        // Parse form
        let fields = match parse_form_data(req).await {
            Ok(fields) => fields,
            Err(err) => return err,
        };

        enum Response {
            Success,
            Failed,
            InvalidCode,
        }

        let code = if let Some(oauth) = fields
            .get("code")
            .and_then(|code| self.oauth_codes.get(code))
        {
            if (STATUS_PENDING..STATUS_PENDING + self.config.oauth_max_auth_attempts)
                .contains(&oauth.status.load(atomic::Ordering::Relaxed))
            {
                if let (Some(email), Some(password)) = (fields.get("email"), fields.get("password"))
                {
                    if let Some(id) = self.authenticate_with_token(email, password).await {
                        oauth
                            .account_id
                            .store(id.primary_id(), atomic::Ordering::Relaxed);
                        oauth
                            .status
                            .store(STATUS_AUTHORIZED, atomic::Ordering::Relaxed);
                        Response::Success
                    } else {
                        oauth.status.fetch_add(1, atomic::Ordering::Relaxed);
                        Response::Failed
                    }
                } else {
                    Response::Failed
                }
            } else {
                Response::InvalidCode
            }
        } else {
            Response::InvalidCode
        };

        let mut response = String::with_capacity(
            OAUTH_HTML_HEADER.len()
                + OAUTH_HTML_LOGIN_HEADER_DEVICE.len()
                + OAUTH_HTML_LOGIN_CODE.len()
                + OAUTH_HTML_LOGIN_FORM.len()
                + OAUTH_HTML_FOOTER.len()
                + USER_CODE_LEN
                + 17,
        );
        response.push_str(&OAUTH_HTML_HEADER.replace("@@@", "/auth"));

        match code {
            Response::Success => {
                response.push_str(OAUTH_HTML_LOGIN_SUCCESS);
            }
            Response::Failed => {
                response.push_str(OAUTH_HTML_LOGIN_HEADER_FAILED);
                response.push_str(&OAUTH_HTML_LOGIN_CODE.replace(
                    "@@@",
                    fields.get("code").map(|s| s.as_str()).unwrap_or_default(),
                ));
                response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", "about:blank"));
            }
            Response::InvalidCode => {
                response.push_str(
                    &OAUTH_HTML_ERROR.replace("@@@", "Invalid or expired authentication code."),
                );
            } /*Response::Error => {
                  response.push_str(&OAUTH_HTML_ERROR.replace(
                      "@@@",
                      "There was a problem processing your request, please try again later.",
                  ));
              }*/
        }

        response.push_str(OAUTH_HTML_FOOTER);

        HtmlResponse::new(response).into_http_response()
    }
}
