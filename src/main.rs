use axum::{routing::post, Router};

use take_home::handlers;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/encrypt", post(handlers::encryption::encrypt))
        .route("/decrypt", post(handlers::encryption::decrypt));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
