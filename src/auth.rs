use oauth2::basic::BasicClient;

// Alternatively, this can be `` or a custom client.
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest, HttpResponse,
    RedirectUrl, Scope, TokenUrl,
};
use std::env;
use std::future::Future;
//use std::io::{BufRead, BufReader, Write};

use anyhow::{Error, Ok, Result};
use spin_sdk::http::{IntoResponse, Params, Request, Response};
pub fn index(_req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(Response::new(200, INDEX_HTML))
}

pub fn authorize(_req: Request, _params: Params) -> Result<impl IntoResponse> {
    let client = create_client();
    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // .add_scope(Scope::new("public_repo".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    let mut res = Response::new(307, "");
    res.set_header("Location", authorize_url.to_string());
    Ok(res)
}

pub async fn github_callback(_req: Request, params: Params) -> Result<impl IntoResponse> {
    let query = _req.query();
    let mut code: Option<AuthorizationCode> = None;
    //let state;
    //code=aca10b34c111cf8d106a&state=gogo-je-debil
    for pair in query.split("&") {
        let mut iter = pair.split("=");
        let key = iter.next().unwrap();
        let value = iter.next().unwrap();
        if key == "code" {
            code = Some(AuthorizationCode::new(value.to_string()));
        } /*else if key == "state" {
              state = CsrfToken::new(value.to_string());
          }*/
    }
    if code.is_none() {
        return Ok(Response::new(400, "Missing code"));
    }
    let code = code.unwrap();
    println!("Github returned the following code:\n{:?}\n", code);

    //Ok(Response::new(200, format!("Tady je tvju code: {:?}", code)))

    let client = create_client();
    let token_res = client.exchange_code(code).request_async(make_req).await?;

    Ok(Response::new(200, ()))
}

#[derive(Debug, thiserror::Error)]
pub enum XError {
    #[error("curl request failed")]
    Bad(),
}

async fn make_req<E>(req: HttpRequest) -> core::result::Result<HttpResponse, XError> {
    let method: spin_sdk::http::Method = match req.method.as_str() {
        "GET" => spin_sdk::http::Method::Get,
        "POST" => spin_sdk::http::Method::Post,
        "PUT" => spin_sdk::http::Method::Put,
        "DELETE" => spin_sdk::http::Method::Delete,
        _ => return core::result::Result::Err(Error::msg("Invalid method")).unwrap(),
    };
    let request = Request::builder()
        .method(method)
        .uri(req.url.as_str())
        .build();

    // Send the request and await the response
    let response = spin_sdk::http::send(request).await;
    if response.is_err() {
        return core::result::Result::Err(XError::Bad());
    }
    let response: spin_sdk::http::IncomingResponse = response.unwrap();

    let mut response_headers = http::HeaderMap::new();

    for header in response.headers().entries() {
        let h = header.clone();
        let key = h.0.clone().as_str();
        let value = http::HeaderValue::from_bytes(&header.1);
        if value.is_err() {
            return core::result::Result::Err(XError::Bad());
        }
        let value = value.unwrap();
        response_headers.append(key, value);
    }

    let status = http::status::StatusCode::from_u16(response.status());
    if status.is_err() {
        return core::result::Result::Err(XError::Bad());
    }
    let status = status.unwrap();

    let body = response.into_body().await;
    if body.is_err() {
        return core::result::Result::Err(XError::Bad());
    }
    let body = body.unwrap();

    let res = HttpResponse {
        headers: response_headers,
        body: body,
        status_code: status,
    };
    core::result::Result::Ok(res)
}

fn create_client() -> BasicClient {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET")
            .expect("Missing the GITHUB_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:3000/auth/github/callback".to_string())
            .expect("Invalid redirect URL"),
    );

    client
}
const INDEX_HTML: &str = "<!DOCTYPE html>
        <html>
          <head>
            <title>GOL</title>
          </head>
          <body>
            <h1>Welcome to GOL</h1>
            <form action='auth/authorize'>
                <button type='submit'>Go to GOL with GitHub</button>
            </form>
          </body>
        </html>";
