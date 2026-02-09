use axum::Json;
use serde_json::{Map, Value};

use crate::crypto::base64::Base64Encryptor;
use crate::crypto::encryptor::Encryptor;

pub async fn encrypt(Json(payload): Json<Value>) -> Json<Value> {
    Json(apply_method_to_values(&payload, &|v| {
        Base64Encryptor.encrypt(v)
    }))
}

pub async fn decrypt(Json(payload): Json<Value>) -> Json<Value> {
    Json(apply_method_to_values(&payload, &|v| {
        Base64Encryptor.decrypt(v).unwrap_or(v.clone())
    }))
}

fn apply_method_to_values(values: &Value, method: &dyn Fn(&Value) -> Value) -> Value {
    match values {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, value) in map.iter() {
                out.insert(key.clone(), method(value));
            }
            Value::Object(out)
        }
        other => method(other),
    }
}
