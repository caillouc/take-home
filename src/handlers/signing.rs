use std::sync::LazyLock;

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::crypto::hmac::HMacSigner;
use crate::crypto::signer::Signer;

static SIGNER: LazyLock<HMacSigner> = LazyLock::new(|| {
    HMacSigner::new(b"shared-secret-key".to_vec())
});

pub async fn sign(Json(payload): Json<Value>) -> Json<Value> {
    match payload {
        Value::Object(map) => {
            let signature = SIGNER.sign(&map);
            Json(json!({ "signature": signature }))
        }
        _ => Json(json!({ "error": "expected a JSON object" })),
    }
}

pub async fn verify(Json(payload): Json<Value>) -> StatusCode {
    let signature = payload.get("signature").and_then(|s| s.as_str());
    let data = payload.get("data");

    match (signature, data) {
        (Some(sig), Some(Value::Object(map))) => {
            if SIGNER.verify(map, sig) {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::BAD_REQUEST
            }
        }
        _ => StatusCode::BAD_REQUEST,
    }
}