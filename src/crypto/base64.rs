use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::encryptor::Encryptor;

#[derive(Default)]
pub struct Base64Encryptor;

impl Base64Encryptor {
    pub fn new() -> Self {
        Self
    }
}

impl Encryptor for Base64Encryptor {
    fn encrypt(&self, value: &Value) -> Value {
        let bytes = serde_json::to_vec(value).expect("failed to serialize JSON value");
        let encoded = STANDARD.encode(bytes);
        Value::String(encoded)
    }

    fn decrypt(&self, value: &Value) -> Option<Value> {
        if let Value::String(s) = value {
            if let Ok(decoded) = STANDARD.decode(s) {
                if let Ok(json) = serde_json::from_slice(&decoded) {
                    return Some(json);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypt_string_value() {
        let encryptor = Base64Encryptor;
        let result = encryptor.encrypt(&json!("hello"));
        assert!(result.is_string());
    }

    #[test]
    fn encrypt_then_decrypt_string() {
        let encryptor = Base64Encryptor;
        let original = json!("hello");
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_number() {
        let encryptor = Base64Encryptor;
        let original = json!(42);
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_boolean() {
        let encryptor = Base64Encryptor;
        let original = json!(true);
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_null() {
        let encryptor = Base64Encryptor;
        let original = json!(null);
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_object() {
        let encryptor = Base64Encryptor;
        let original = json!({"key": "value", "num": 123, "empty": ""});
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_array() {
        let encryptor = Base64Encryptor;
        let original = json!([1, "two", false]);
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_then_decrypt_nested_object() {
        let encryptor = Base64Encryptor;
        let original = json!({
            "user": {
                "name": "Alice",
                "address": {
                    "city": "Paris",
                    "zip": 75000
                },
                "tags": ["admin", {"role": "editor", "active": true}]
            },
            "metadata": {
                "version": 1,
                "nested": {
                    "deep": {
                        "value": null
                    }
                }
            }
        });
        let encrypted = encryptor.encrypt(&original);
        let decrypted = encryptor.decrypt(&encrypted).unwrap_or(Value::Null);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn decrypt_invalid_base64_returns_null() {
        let encryptor = Base64Encryptor;
        let result = encryptor.decrypt(&json!("not-valid-base64!!!"));
        assert_eq!(result, None);
    }

    #[test]
    fn decrypt_valid_base64_but_invalid_json_returns_null() {
        let encryptor = Base64Encryptor;
        let invalid_json = STANDARD.encode("this is not json".as_bytes());
        let result = encryptor.decrypt(&json!(invalid_json));
        assert_eq!(result, None);
    }

    #[test]
    fn decrypt_non_string_value_returns_null() {
        let encryptor = Base64Encryptor;
        assert_eq!(encryptor.decrypt(&json!(12345)), None);
        assert_eq!(encryptor.decrypt(&json!(true)), None);
        assert_eq!(encryptor.decrypt(&json!(null)), None);
    }
}
