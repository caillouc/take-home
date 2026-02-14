use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn app() -> Router {
    Router::new()
        .route("/sign", post(take_home::handlers::signing::sign))
        .route("/verify", post(take_home::handlers::signing::verify))
}

async fn post_json(app: Router, uri: &str, body: Value) -> (StatusCode, Option<Value>) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).ok();
    (status, value)
}

// ── /sign endpoint ─────────────────────────────────────────────────

#[tokio::test]
async fn sign_returns_200() {
    let (status, _) = post_json(app(), "/sign", json!({"message": "hello"})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn sign_returns_signature_property() {
    // README: Output is a JSON payload with a unique "signature" property
    let (_, body) = post_json(
        app(),
        "/sign",
        json!({"message": "Hello World", "timestamp": 1616161616}),
    )
    .await;
    let body = body.expect("response should be valid JSON");
    assert!(
        body.get("signature").is_some(),
        "response must contain a 'signature' property"
    );
    assert!(body["signature"].is_string(), "signature must be a string");
}

#[tokio::test]
async fn sign_property_order_does_not_affect_signature() {
    // README: The order of properties should not affect the signature
    let (_, body_a) = post_json(
        app(),
        "/sign",
        json!({"message": "Hello World", "timestamp": 1616161616}),
    )
    .await;

    let (_, body_b) = post_json(
        app(),
        "/sign",
        json!({"timestamp": 1616161616, "message": "Hello World"}),
    )
    .await;

    let sig_a = body_a.unwrap()["signature"].as_str().unwrap().to_string();
    let sig_b = body_b.unwrap()["signature"].as_str().unwrap().to_string();
    assert_eq!(
        sig_a, sig_b,
        "signature must be the same regardless of property order"
    );
}

#[tokio::test]
async fn sign_different_payloads_produce_different_signatures() {
    let (_, body_a) = post_json(app(), "/sign", json!({"message": "Hello World"})).await;
    let (_, body_b) = post_json(app(), "/sign", json!({"message": "Goodbye World"})).await;

    let sig_a = body_a.unwrap()["signature"].as_str().unwrap().to_string();
    let sig_b = body_b.unwrap()["signature"].as_str().unwrap().to_string();
    assert_ne!(
        sig_a, sig_b,
        "different payloads must produce different signatures"
    );
}

#[tokio::test]
async fn sign_is_deterministic() {
    // Signing the same payload twice should yield the same signature
    let payload = json!({"user": "alice", "action": "login"});
    let (_, body_a) = post_json(app(), "/sign", payload.clone()).await;
    let (_, body_b) = post_json(app(), "/sign", payload).await;

    let sig_a = body_a.unwrap()["signature"].as_str().unwrap().to_string();
    let sig_b = body_b.unwrap()["signature"].as_str().unwrap().to_string();
    assert_eq!(sig_a, sig_b);
}

// ── /verify endpoint ───────────────────────────────────────────────

#[tokio::test]
async fn verify_valid_signature_returns_204() {
    // README: HTTP 204 (No Content) if signature is valid
    let payload = json!({"message": "Hello World", "timestamp": 1616161616});
    let (_, sign_body) = post_json(app(), "/sign", payload.clone()).await;
    let signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _) = post_json(
        app(),
        "/verify",
        json!({"signature": signature, "data": payload}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn verify_valid_signature_with_reordered_data_returns_204() {
    // README: The same input object with the order of properties changed must produce the same signature
    let (_, sign_body) = post_json(
        app(),
        "/sign",
        json!({"message": "Hello World", "timestamp": 1616161616}),
    )
    .await;
    let signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify with properties in different order
    let (status, _) = post_json(
        app(),
        "/verify",
        json!({
            "signature": signature,
            "data": {"timestamp": 1616161616, "message": "Hello World"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn verify_tampered_payload_returns_400() {
    // README: tampered payload → 400 HTTP response
    let (_, sign_body) = post_json(
        app(),
        "/sign",
        json!({"message": "Hello World", "timestamp": 1616161616}),
    )
    .await;
    let signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _) = post_json(
        app(),
        "/verify",
        json!({
            "signature": signature,
            "data": {"timestamp": 1616161616, "message": "Goodbye World"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_tampered_signature_returns_400() {
    let payload = json!({"message": "Hello World", "timestamp": 1616161616});
    let (_, sign_body) = post_json(app(), "/sign", payload.clone()).await;
    let mut signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    // Tamper with the signature
    let last = signature.pop().unwrap();
    signature.push(if last == 'a' { 'b' } else { 'a' });

    let (status, _) = post_json(
        app(),
        "/verify",
        json!({"signature": signature, "data": payload}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_missing_signature_returns_400() {
    let (status, _) = post_json(app(), "/verify", json!({"data": {"message": "Hello"}})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_missing_data_returns_400() {
    let (status, _) = post_json(app(), "/verify", json!({"signature": "abc123"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_non_object_data_returns_400() {
    // README: "data" must be a JSON object
    let (status, _) = post_json(
        app(),
        "/verify",
        json!({"signature": "abc123", "data": "not an object"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── sign → verify round-trip ───────────────────────────────────────

#[tokio::test]
async fn sign_then_verify_roundtrip() {
    // README: a payload signed with /sign can be successfully verified with /verify
    let payload = json!({
        "user": "alice",
        "role": "admin",
        "exp": 1700000000
    });

    let (_, sign_body) = post_json(app(), "/sign", payload.clone()).await;
    let signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _) = post_json(
        app(),
        "/verify",
        json!({"signature": signature, "data": payload}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn sign_then_verify_roundtrip_with_nested_values() {
    let payload = json!({
        "user": "bob",
        "metadata": {"level": 5, "tags": ["a", "b"]}
    });

    let (_, sign_body) = post_json(app(), "/sign", payload.clone()).await;
    let signature = sign_body.unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _) = post_json(
        app(),
        "/verify",
        json!({"signature": signature, "data": payload}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ── HTTP-level edge cases ──────────────────────────────────────────

#[tokio::test]
async fn sign_invalid_content_type_returns_error() {
    let request = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("Content-Type", "text/plain")
        .body(Body::from("not json"))
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn verify_invalid_content_type_returns_error() {
    let request = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("Content-Type", "text/plain")
        .body(Body::from("not json"))
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn get_sign_returns_method_not_allowed() {
    let request = Request::builder()
        .method("GET")
        .uri("/sign")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn get_verify_returns_method_not_allowed() {
    let request = Request::builder()
        .method("GET")
        .uri("/verify")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
