use anyhow::Result;
use spin_sdk::http::{IntoResponse, Params, Request, Response};

pub fn github_callback(_req: Request, params: Params) -> Result<impl IntoResponse> {
    dbg!("github_callback {}", params);
    Ok(Response::new(200, ""))
}

pub fn index(_req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(Response::new(200, INDEX_HTML))
}

const INDEX_HTML: &str = "<!DOCTYPE html>
        <html>
          <head>
            <title>GOL</title>
          </head>
          <body>
            <h1>Welcome to GOL</h1>
            <form action='https://github.com/login/oauth/authorize'>
                <button type='submit'>Go to GOL with GitHub</button>
                <input type='hidden' name='client_id' value='Iv1.69cabc48ec7f3d52'>
                <input type='hidden' name='state' value='gogo-je-debil'>
            </form>
          </body>
        </html>";
