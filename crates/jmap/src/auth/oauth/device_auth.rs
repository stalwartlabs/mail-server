use std::{
    sync::{atomic, Arc},
    time::Instant,
};

use hyper::StatusCode;
use store::rand::{
    distributions::{Alphanumeric, Standard},
    thread_rng,
};

use crate::auth::oauth::{
    OAUTH_HTML_ERROR, OAUTH_HTML_LOGIN_HEADER_FAILED, OAUTH_HTML_LOGIN_SUCCESS, STATUS_AUTHORIZED,
};

use super::{
    DeviceAuthGet, DeviceAuthResponse, OAuthCode, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN,
    OAUTH_HTML_FOOTER, OAUTH_HTML_HEADER, OAUTH_HTML_LOGIN_CODE, OAUTH_HTML_LOGIN_FORM,
    OAUTH_HTML_LOGIN_HEADER_DEVICE, STATUS_PENDING, USER_CODE_ALPHABET, USER_CODE_LEN,
};

// Device authorization endpoint
pub async fn handle_device_auth<T>(
    core: web::Data<JMAPServer<T>>,
    params: web::Form<DeviceAuthRequest>,
) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    // Validate clientId
    if params.client_id.len() > CLIENT_ID_MAX_LEN {
        return HttpResponse::BadRequest().body("Client ID is too long");
    }

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
        expiry: Instant::now(),
        client_id: params.into_inner().client_id,
        redirect_uri: None,
    });
    core.oauth_codes
        .insert(device_code.clone(), oauth_code.clone())
        .await;
    core.oauth_codes.insert(user_code.clone(), oauth_code).await;

    // Build response
    let response = DeviceAuthResponse {
        verification_uri: format!("{}/auth", core.base_session.base_url()),
        verification_uri_complete: format!(
            "{}/auth/code?={}",
            core.base_session.base_url(),
            user_code
        ),
        device_code,
        user_code,
        expires_in: core.oauth.expiry_user_code,
        interval: 5,
    };

    HttpResponse::build(StatusCode::OK)
        .content_type("application/json")
        .body(serde_json::to_string(&response).unwrap_or_default())
}

// Device authorization flow, renders the authorization page
pub async fn handle_user_device_auth<T>(params: web::Query<DeviceAuthGet>) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    let code = params.code.as_deref().unwrap_or("");
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
    response.push_str(&OAUTH_HTML_LOGIN_CODE.replace("@@@", code));
    response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", "about:blank"));
    response.push_str(OAUTH_HTML_FOOTER);

    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(response)
}

// Handles POST request from the device authorization form
pub async fn handle_user_device_auth_post<T>(
    core: web::Data<JMAPServer<T>>,
    params: web::Form<DeviceAuthPost>,
) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    enum Response {
        Success,
        Failed,
        InvalidCode,
        Error,
    }

    let params = params.into_inner();
    let code = if let Some(oauth) = params
        .code
        .as_ref()
        .and_then(|code| core.oauth_codes.get(code))
    {
        if (STATUS_PENDING..STATUS_PENDING + core.oauth.max_auth_attempts)
            .contains(&oauth.status.load(atomic::Ordering::Relaxed))
            && oauth.expiry.elapsed().as_secs() < core.oauth.expiry_user_code
        {
            if let (Some(email), Some(password)) = (params.email, params.password) {
                let store = core.store.clone();
                match core
                    .spawn_worker(move || store.authenticate(&email, &password))
                    .await
                {
                    Ok(Some(account_id)) => {
                        oauth
                            .account_id
                            .store(account_id, atomic::Ordering::Relaxed);
                        oauth
                            .status
                            .store(STATUS_AUTHORIZED, atomic::Ordering::Relaxed);
                        Response::Success
                    }
                    Ok(None) => {
                        oauth.status.fetch_add(1, atomic::Ordering::Relaxed);
                        Response::Failed
                    }
                    Err(_) => Response::Error,
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
            response.push_str(
                &OAUTH_HTML_LOGIN_CODE.replace("@@@", params.code.as_deref().unwrap_or("")),
            );
            response.push_str(&OAUTH_HTML_LOGIN_FORM.replace("@@@", "about:blank"));
        }
        Response::InvalidCode => {
            response.push_str(
                &OAUTH_HTML_ERROR.replace("@@@", "Invalid or expired authentication code."),
            );
        }
        Response::Error => {
            response.push_str(&OAUTH_HTML_ERROR.replace(
                "@@@",
                "There was a problem processing your request, please try again later.",
            ));
        }
    }

    response.push_str(OAUTH_HTML_FOOTER);

    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(response)
}
