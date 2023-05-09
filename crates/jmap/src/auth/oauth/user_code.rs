use std::{sync::Arc, time::Instant};

use hyper::{header, StatusCode};
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use store::rand::{distributions::Alphanumeric, thread_rng};

use super::{
    CodeAuthRequest, OAuthCode, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN, OAUTH_HTML_FOOTER,
    OAUTH_HTML_HEADER, OAUTH_HTML_LOGIN_CODE_HIDDEN, OAUTH_HTML_LOGIN_FORM,
    OAUTH_HTML_LOGIN_HEADER_CLIENT, OAUTH_HTML_LOGIN_HEADER_FAILED, STATUS_AUTHORIZED,
};

// Code authorization flow, handles an authorization request
pub async fn handle_user_code_auth<T>(params: web::Query<CodeAuthRequest>) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    // Validate clientId
    if params.client_id.len() > CLIENT_ID_MAX_LEN {
        return HttpResponse::BadRequest().body("Client ID is too long");
    } else if !params.redirect_uri.starts_with("https://") {
        return HttpResponse::BadRequest().body("Redirect URI must be HTTPS");
    }

    let params = params.into_inner();
    let mut cancel_link = format!("{}?error=access_denied", params.redirect_uri);
    if let Some(state) = &params.state {
        let _ = write!(cancel_link, "&state={}", state);
    }
    let code = String::from_utf8(
        base64_encode(&bincode::serialize(&(1u32, params)).unwrap_or_default()).unwrap_or_default(),
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

    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(response)
}

// Handles POST request from the code authorization form
pub async fn handle_user_code_auth_post<T>(
    core: web::Data<JMAPServer<T>>,
    params: web::Form<CodeAuthForm>,
) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    let mut auth_code = None;
    let params = params.into_inner();
    let (auth_attempts, code_req) = match base64_decode(params.code.as_bytes())
        .and_then(|bytes| bincode::deserialize::<(u32, CodeAuthRequest)>(&bytes).ok())
    {
        Some(code) => code,
        None => {
            return HttpResponse::BadRequest().body("Failed to deserialize code.");
        }
    };

    // Authenticate user
    if let (Some(email), Some(password)) = (params.email, params.password) {
        let store = core.store.clone();

        if let Ok(Some(account_id)) = core
            .spawn_worker(move || store.authenticate(&email, &password))
            .await
        {
            // Generate client code
            let client_code = thread_rng()
                .sample_iter(Alphanumeric)
                .take(DEVICE_CODE_LEN)
                .map(char::from)
                .collect::<String>();

            // Add client code
            core.oauth_codes
                .insert(
                    client_code.clone(),
                    Arc::new(OAuthCode {
                        status: STATUS_AUTHORIZED.into(),
                        account_id: account_id.into(),
                        expiry: Instant::now(),
                        client_id: code_req.client_id.clone(),
                        redirect_uri: code_req.redirect_uri.clone().into(),
                    }),
                )
                .await;

            auth_code = client_code.into();
        }
    }

    // Build redirect link
    let mut redirect_link = if let Some(auth_code) = &auth_code {
        format!("{}?code={}", code_req.redirect_uri, auth_code)
    } else {
        format!("{}?error=access_denied", code_req.redirect_uri)
    };
    if let Some(state) = &code_req.state {
        let _ = write!(redirect_link, "&state={}", state);
    }

    if auth_code.is_none() && (auth_attempts < core.oauth.max_auth_attempts) {
        let code = String::from_utf8(
            base64_encode(&bincode::serialize(&(auth_attempts + 1, code_req)).unwrap_or_default())
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

        HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(response)
    } else {
        HttpResponse::build(StatusCode::TEMPORARY_REDIRECT)
            .insert_header((header::LOCATION, redirect_link))
            .finish()
    }
}
