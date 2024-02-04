use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use spin_sdk::{
    http::{IntoResponse, Params, Request, Response, Router},
    http_component,
    key_value::Store,
};

#[derive(Serialize, Deserialize, Debug)]
struct User {
    user_name: Option<String>,
    location: Option<String>,
}

#[http_component]
fn handle_route(req: Request) -> Response {
    let mut router = Router::new();
    router.get("/user/:userName", api::get_user);
    router.put("/user/", api::create_user);
    router.handle(req)
}

mod api {
    use super::*;

    pub fn get_user(_req: Request, params: Params) -> Result<impl IntoResponse> {
        println!("get_user");
        let user_name = params.get("userName");
        if user_name.is_none() {
            return Ok(Response::new(400, "user name is required"));
        }
        let user_name = user_name.unwrap();

        let store = Store::open_default()?;
        let user_json = store.get(user_name)?;
        if user_json.is_none() {
            return Ok(Response::new(404, format!("user {} not found", user_name)));
        }
        //let user_json = user_json.unwrap();

        // let user: User = serde_json::from_slice(&user_json)?;
        Ok(Response::new(200, user_json))
    }

    pub fn create_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
        println!("create_user");
        let body_bytes = req.body().to_vec();
        let user: User = serde_json::from_slice(&body_bytes)?;
        dbg!("create_user {}", &user);

        if user.user_name.is_none() {
            return Ok(Response::new(400, "user name is required"));
        }
        let user_name = user.user_name.clone().unwrap();
        if user_name.is_empty() {
            return Ok(Response::new(400, "user name is required"));
        }
        let store = Store::open_default()?;
        let user_exists = store.get(&user_name)?;
        if !user_exists.is_none() {
            return Ok(Response::new(
                400,
                format!("user {} already exists", user_name),
            ));
        }
        store.set_json(user_name, &user)?;
        Ok(Response::new(200, ()))
    }
}
