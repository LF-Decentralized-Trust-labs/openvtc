use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::{Context, Result, bail};
use openvtc::maintainers::Maintainer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use tracing::error;

/// OpenVTC Configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub maintainers: Vec<Maintainer>,
    pub mediator: String,
    pub our_did: String,
    pub secrets: Vec<Secret>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path).context(format!(
            "Couldn't load openvtc configuration file ({}) from disk",
            &path
        ))?;

        reject_plaintext_private_keys(&raw)?;

        match serde_json::from_str(&raw) {
            Ok(s) => Ok(s),
            Err(e) => {
                error!("ERROR: Couldn't Deserialize Config file. Reason: {}", e);
                bail!("Deserialization error")
            }
        }
    }
}

fn reject_plaintext_private_keys(raw: &str) -> Result<()> {
    if contains_plaintext_private_key_material(raw) {
        bail!("Refusing to load config containing plaintext private key material")
    }

    Ok(())
}

fn contains_plaintext_private_key_material(raw: &str) -> bool {
    // Fast fail-closed guard for common private-key field names.
    let lowercase = raw.to_ascii_lowercase();
    if lowercase.contains("\"privatekeyjwk\"") {
        return true;
    }

    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return false;
    };

    contains_jwk_private_components(&value)
}

fn contains_jwk_private_components(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            if map.contains_key("privateKeyJwk") {
                return true;
            }

            if map.contains_key("d") && map.contains_key("kty") {
                return true;
            }

            map.values().any(contains_jwk_private_components)
        }
        Value::Array(items) => items.iter().any(contains_jwk_private_components),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::contains_plaintext_private_key_material;

    #[test]
    fn detects_private_key_jwk_pattern() {
        let raw = r#"{
            "secrets": [
                {
                    "privateKeyJwk": {"kty": "OKP", "d": "secret", "x": "public"}
                }
            ]
        }"#;

        assert!(contains_plaintext_private_key_material(raw));
    }

    #[test]
    fn detects_d_and_kty_jwk_private_material_pattern() {
        let raw = r#"{
            "secrets": [
                {
                    "kty": "OKP",
                    "d": "secret"
                }
            ]
        }"#;

        assert!(contains_plaintext_private_key_material(raw));
    }

    #[test]
    fn safe_config_shape_does_not_trigger() {
        let raw = r#"{
            "maintainers": [{"alias": "Ada", "did": "did:webvh:example"}],
            "mediator": "did:webvh:mediator",
            "our_did": "did:webvh:ours",
            "secrets": []
        }"#;

        assert!(!contains_plaintext_private_key_material(raw));
    }

    #[test]
    fn nested_secrets_array_case_triggers() {
        let raw = r#"{
            "maintainers": [{"alias": "Ada", "did": "did:webvh:example"}],
            "mediator": "did:webvh:mediator",
            "our_did": "did:webvh:ours",
            "secrets": [
                {
                    "nested": {
                        "inner": {
                            "kty": "OKP",
                            "d": "secret"
                        }
                    }
                }
            ]
        }"#;

        assert!(contains_plaintext_private_key_material(raw));
    }
}
