mod auth;
mod user;
use spin_sdk::{
    http::{Request, Response, Router},
    http_component,
};

#[http_component]
fn handle_route(req: Request) -> Response {
    let mut router = Router::new();
    router.get("/", auth::index);
    router.get("/user/:userName", user::get_user);
    router.put("/user/", user::create_user);
    router.get("/auth/github/callback", auth::github_callback);
    router.handle(req)
}
