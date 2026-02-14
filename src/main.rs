use axum::{Router, routing::post};

use take_home::handlers;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/encrypt", post(handlers::encryption::encrypt))
        .route("/decrypt", post(handlers::encryption::decrypt))
        .route("/sign", post(handlers::signing::sign))
        .route("/verify", post(handlers::signing::verify));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("Server running on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}
