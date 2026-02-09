use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    Router::new()
        .route("/encrypt", post(take_home::handlers::encryption::encrypt))
        .route("/decrypt", post(take_home::handlers::encryption::decrypt))
}

async fn post_json(app: Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    (status, value)
}

#[tokio::test]
async fn encrypt_returns_200() {
    let (status, _) = post_json(app(), "/encrypt", json!({"hello": "world"})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn decrypt_returns_200() {
    let (status, _) = post_json(app(), "/decrypt", json!({"hello": "d29ybGQ="})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn encrypt_returns_base64_values() {
    let (_, body) = post_json(app(), "/encrypt", json!({"name": "Alice"})).await;
    // All values should be base64-encoded strings
    assert!(body["name"].is_string());
}

#[tokio::test]
async fn encrypt_then_decrypt_roundtrip() {
    let original = json!({"name": "Alice", "age": 30, "active": true});

    let (_, encrypted) = post_json(app(), "/encrypt", original.clone()).await;
    // Encrypted values should differ from originals
    assert_ne!(encrypted, original);

    let (_, decrypted) = post_json(app(), "/decrypt", encrypted).await;
    assert_eq!(decrypted, original);
}

#[tokio::test]
async fn encrypt_then_decrypt_nested_json() {
    let original = json!({
        "user": {
            "name": "Bob",
            "address": {
                "city": "Paris",
                "zip": 75000
            }
        }
    });

    let (_, encrypted) = post_json(app(), "/encrypt", original.clone()).await;
    let (_, decrypted) = post_json(app(), "/decrypt", encrypted).await;
    assert_eq!(decrypted, original);
}

#[tokio::test]
async fn encrypt_then_decrypt_with_null_and_empty_values() {
    let original = json!({
        "empty_string": "",
        "null_value": null,
        "zero": 0,
        "false_val": false
    });

    let (_, encrypted) = post_json(app(), "/encrypt", original.clone()).await;
    let (_, decrypted) = post_json(app(), "/decrypt", encrypted).await;
    assert_eq!(decrypted, original);
}

#[tokio::test]
async fn encrypt_preserves_keys() {
    let original = json!({"key_a": "value_a", "key_b": "value_b"});

    let (_, encrypted) = post_json(app(), "/encrypt", original).await;
    // Keys should remain unchanged, only values are encrypted
    assert!(encrypted.get("key_a").is_some());
    assert!(encrypted.get("key_b").is_some());
}

#[tokio::test]
async fn invalid_content_type_returns_error() {
    let request = Request::builder()
        .method("POST")
        .uri("/encrypt")
        .header("Content-Type", "text/plain")
        .body(Body::from("not json"))
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn get_request_returns_method_not_allowed() {
    let request = Request::builder()
        .method("GET")
        .uri("/encrypt")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let request = Request::builder()
        .method("POST")
        .uri("/unknown")
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Depth-1 encryption tests (from README spec) ---

#[tokio::test]
async fn encrypt_only_at_depth_1() {
    // From README: nested objects should be encrypted as a whole, not recursively
    let original = json!({
        "name": "John Doe",
        "age": 30,
        "contact": {
            "email": "john@example.com",
            "phone": "123-456-7890"
        }
    });

    let (_, encrypted) = post_json(app(), "/encrypt", original).await;

    // All depth-1 values should be base64 strings
    assert!(encrypted["name"].is_string());
    assert!(encrypted["age"].is_string());
    assert!(encrypted["contact"].is_string());

    // The nested object should NOT have its keys visible — it's encrypted as a whole
    assert!(encrypted.get("email").is_none());
    assert!(encrypted.get("phone").is_none());
}

#[tokio::test]
async fn encrypt_then_decrypt_readme_example() {
    // Exact example from README
    let original = json!({
        "name": "John Doe",
        "age": 30,
        "contact": {
            "email": "john@example.com",
            "phone": "123-456-7890"
        }
    });

    let (_, encrypted) = post_json(app(), "/encrypt", original.clone()).await;

    // Keys must be preserved
    assert!(encrypted.get("name").is_some());
    assert!(encrypted.get("age").is_some());
    assert!(encrypted.get("contact").is_some());

    let (_, decrypted) = post_json(app(), "/decrypt", encrypted).await;
    assert_eq!(decrypted, original);
}

// --- Unencrypted field passthrough tests (from README spec) ---

#[tokio::test]
async fn decrypt_leaves_unencrypted_fields_unchanged() {
    // From README: unencrypted properties must remain unchanged
    let original = json!({
        "name": "John Doe",
        "age": 30,
        "contact": {
            "email": "john@example.com",
            "phone": "123-456-7890"
        }
    });

    // Encrypt first to get valid encrypted values
    let (_, mut encrypted) = post_json(app(), "/encrypt", original).await;

    // Add an unencrypted field (like README example with birth_date)
    encrypted["birth_date"] = json!("1998-11-19");

    let (_, decrypted) = post_json(app(), "/decrypt", encrypted).await;

    // Encrypted fields should be restored
    assert_eq!(decrypted["name"], json!("John Doe"));
    assert_eq!(decrypted["age"], json!(30));
    assert_eq!(decrypted["contact"]["email"], json!("john@example.com"));
    assert_eq!(decrypted["contact"]["phone"], json!("123-456-7890"));

    // Unencrypted field must remain unchanged
    assert_eq!(decrypted["birth_date"], json!("1998-11-19"));
}

#[tokio::test]
async fn decrypt_mixed_encrypted_and_plain_values() {
    // Mix of encrypted values and plain unencrypted values
    let original = json!({"secret": "classified", "count": 42});
    let (_, encrypted) = post_json(app(), "/encrypt", original).await;

    // Build a payload with one encrypted value and one plain value
    let mixed = json!({
        "secret": encrypted["secret"],
        "plain_text": "not encrypted",
        "plain_number": 99
    });

    let (_, decrypted) = post_json(app(), "/decrypt", mixed).await;
    assert_eq!(decrypted["secret"], json!("classified"));
    assert_eq!(decrypted["plain_text"], json!("not encrypted"));
    assert_eq!(decrypted["plain_number"], json!(99));
}

#[tokio::test]
async fn decrypt_all_plain_values_returns_them_unchanged() {
    // If nothing was encrypted, decrypt should return everything as-is
    let payload = json!({
        "name": "Alice",
        "age": 25,
        "active": true
    });

    let (_, decrypted) = post_json(app(), "/decrypt", payload.clone()).await;
    assert_eq!(decrypted, payload);
}

#[tokio::test]
async fn encrypt_flat_json_all_values_become_strings() {
    // Depth-1 encryption: every value regardless of type becomes a base64 string
    let original = json!({
        "string_val": "hello",
        "number_val": 123,
        "bool_val": true,
        "null_val": null
    });

    let (_, encrypted) = post_json(app(), "/encrypt", original).await;

    assert!(encrypted["string_val"].is_string());
    assert!(encrypted["number_val"].is_string());
    assert!(encrypted["bool_val"].is_string());
    assert!(encrypted["null_val"].is_string());
}
