use serde_json::{Map, Value};

pub trait Signer {
    fn sign(&self, map: &Map<String, Value>) -> Value;
    fn verify(&self, map: &Map<String, Value>, signature: &str) -> bool;
}
