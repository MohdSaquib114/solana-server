use axum::{
    routing::get,
    response::Html,
    Router,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // define one route: GET /
    let app = Router::new().route("/", get(root_handler));

    // listen on localhost:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🚀 Server running at http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// GET /
async fn root_handler() -> Html<&'static str> {
    Html("<h1>Hello from Axum!</h1>")
}
