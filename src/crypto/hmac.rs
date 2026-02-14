use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::crypto::signer::Signer;

pub struct HMacSigner {
    key: Vec<u8>,
}

impl HMacSigner {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl HMacSigner {
    /// Builds a deterministic string from a JSON object by sorting entries
    /// alphabetically by key.
    ///
    /// NOTE: Nested object values are serialized using `serde_json`'s `Display`,
    /// whose key order depends on insertion order (not sorted). This means two
    /// objects that are semantically identical but have differently-ordered nested
    /// keys would produce different signatures. Because the API operates at
    /// depth 1 (same as `/encrypt`), this is acceptable for the current scope.
    /// A recursive canonicalization (sorting keys at every depth) would remove
    /// this limitation if deeper guarantees were needed.
    fn map_to_string(&self, map: &Map<String, Value>) -> String {
        let mut to_sign: Vec<String> = map.iter().map(|(k, v)| format!("{k}={v};")).collect();
        to_sign.sort();
        to_sign.join("")
    }
}

impl Signer for HMacSigner {
    fn sign(&self, map: &Map<String, Value>) -> Value {
        let concatenated = self.map_to_string(map);

        let mut signature = Hmac::<Sha256>::new_from_slice(self.key.as_slice()).unwrap();
        signature.update(concatenated.as_bytes());
        let result = signature.finalize();
        Value::String(format!("{:x}", result.into_bytes()))
    }

    /// Verifies a signature against a map using constant-time comparison
    /// to prevent timing attacks.
    fn verify(&self, map: &Map<String, Value>, signature: &str) -> bool {
        let concatenated = self.map_to_string(map);

        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_slice()).unwrap();
        mac.update(concatenated.as_bytes());

        // Decode the hex signature back to bytes
        let sig_bytes: Result<Vec<u8>, _> = (0..signature.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&signature[i..i + 2], 16))
            .collect();

        match sig_bytes {
            Ok(bytes) => mac.verify_slice(&bytes).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value, json};

    fn make_signer() -> HMacSigner {
        HMacSigner::new(b"super-secret-key".to_vec())
    }

    fn sample_map() -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("name".into(), json!("Alice"));
        map.insert("age".into(), json!(30));
        map
    }

    // ── map_to_string ──────────────────────────────────────────────

    #[test]
    fn map_to_string_sorts_keys_alphabetically() {
        let signer = make_signer();
        let map = sample_map(); // keys: "age", "name"
        let result = signer.map_to_string(&map);
        assert_eq!(result, "age=30;name=\"Alice\";");
    }

    #[test]
    fn map_to_string_empty_map_returns_empty_string() {
        let signer = make_signer();
        let map = Map::new();
        assert_eq!(signer.map_to_string(&map), "");
    }

    #[test]
    fn map_to_string_single_entry() {
        let signer = make_signer();
        let mut map = Map::new();
        map.insert("key".into(), json!("value"));
        assert_eq!(signer.map_to_string(&map), "key=\"value\";");
    }

    // ── sign ───────────────────────────────────────────────────────

    #[test]
    fn sign_returns_hex_string() {
        let signer = make_signer();
        let map = sample_map();
        let signature = signer.sign(&map);
        // Signature should be a hex-encoded string (64 hex chars for SHA-256)
        let sig_str = signature.as_str().unwrap();
        assert_eq!(sig_str.len(), 64);
        assert!(sig_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_is_deterministic() {
        let signer = make_signer();
        let map = sample_map();
        let sig1 = signer.sign(&map);
        let sig2 = signer.sign(&map);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_differs_for_different_keys() {
        let signer_a = HMacSigner::new(b"key-a".to_vec());
        let signer_b = HMacSigner::new(b"key-b".to_vec());
        let map = sample_map();
        assert_ne!(signer_a.sign(&map), signer_b.sign(&map));
    }

    #[test]
    fn sign_differs_for_different_data() {
        let signer = make_signer();
        let map1 = sample_map();
        let mut map2 = Map::new();
        map2.insert("name".into(), json!("Bob"));
        assert_ne!(signer.sign(&map1), signer.sign(&map2));
    }

    // ── verify ─────────────────────────────────────────────────────

    #[test]
    fn verify_returns_true_for_valid_signature() {
        let signer = make_signer();
        let map = sample_map();
        let signature = signer.sign(&map);
        let sig_str = signature.as_str().unwrap();
        assert!(signer.verify(&map, sig_str));
    }

    #[test]
    fn verify_returns_false_for_tampered_data() {
        let signer = make_signer();
        let map = sample_map();
        let signature = signer.sign(&map);
        let sig_str = signature.as_str().unwrap();

        let mut tampered = Map::new();
        tampered.insert("name".into(), json!("Eve"));
        tampered.insert("age".into(), json!(30));
        assert!(!signer.verify(&tampered, sig_str));
    }

    #[test]
    fn verify_returns_false_for_wrong_signature() {
        let signer = make_signer();
        let map = sample_map();
        let wrong_sig = "aa".repeat(32); // valid hex, wrong value
        assert!(!signer.verify(&map, &wrong_sig));
    }

    #[test]
    fn verify_returns_false_for_invalid_hex() {
        let signer = make_signer();
        let map = sample_map();
        assert!(!signer.verify(&map, "not-valid-hex!!"));
    }

    #[test]
    fn verify_returns_false_for_different_key() {
        let signer_a = HMacSigner::new(b"key-a".to_vec());
        let signer_b = HMacSigner::new(b"key-b".to_vec());
        let map = sample_map();
        let sig = signer_a.sign(&map);
        let sig_str = sig.as_str().unwrap();
        assert!(!signer_b.verify(&map, sig_str));
    }

    #[test]
    fn verify_empty_map_round_trip() {
        let signer = make_signer();
        let map = Map::new();
        let sig = signer.sign(&map);
        let sig_str = sig.as_str().unwrap();
        assert!(signer.verify(&map, sig_str));
    }
}
