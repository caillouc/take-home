use serde_json::Value;

pub trait Encryptor {
    fn encrypt(&self, value: &Value) -> Value;
    fn decrypt(&self, value: &Value) -> Option<Value>;
}
