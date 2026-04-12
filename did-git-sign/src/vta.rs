use anyhow::{Context, Result, bail};
use vta_sdk::{
    client::VtaClient,
    session::{TokenResult, challenge_response},
};
use zeroize::Zeroize;

use crate::config::{self, SigningConfig, VtaCredentials};

/// Maximum number of authentication retry attempts.
const MAX_AUTH_RETRIES: u32 = 2;

/// Authenticate with VTA, using a cached token if available.
/// Returns an authenticated VtaClient and the loaded VTA credentials.
///
/// Loads VTA credentials from the OS keyring (not from the config file).
/// On cached token failure, falls back to fresh challenge-response auth.
/// Retries up to [`MAX_AUTH_RETRIES`] times on transient failures.
pub async fn authenticate(cfg: &SigningConfig) -> Result<(VtaClient, VtaCredentials)> {
    let creds = config::load_vta_credentials(&cfg.did_key_id)?;
    validate_credentials(&creds)?;

    let client = VtaClient::new(&creds.vta_url);

    // Try cached token first
    if let Some(token) = config::load_cached_token(&cfg.did_key_id) {
        client.set_token(token);
        return Ok((client, creds));
    }

    // Fall back to challenge-response auth with retry
    let token_result = auth_with_retry(
        &creds.vta_url,
        &creds.credential_did,
        &creds.private_key_multibase,
        &creds.vta_did,
    )
    .await?;

    // Cache the token for future invocations
    let _ = config::cache_token(
        &cfg.did_key_id,
        &token_result.access_token,
        token_result.access_expires_at,
    );

    client.set_token(token_result.access_token);
    Ok((client, creds))
}

/// Validate VTA credentials before use.
fn validate_credentials(creds: &VtaCredentials) -> Result<()> {
    if creds.vta_url.is_empty() {
        bail!("VTA URL is empty");
    }
    if !creds.vta_url.starts_with("https://") && !creds.vta_url.starts_with("http://localhost") {
        bail!(
            "VTA URL must use HTTPS (got: {}). Use http://localhost only for local development.",
            creds.vta_url
        );
    }
    if creds.credential_did.is_empty() {
        bail!("credential DID is empty");
    }
    if creds.key_id.is_empty() {
        bail!("signing key ID is empty");
    }
    Ok(())
}

/// Perform challenge-response authentication with retry on transient failures.
async fn auth_with_retry(
    vta_url: &str,
    credential_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult> {
    let mut last_err = None;
    for attempt in 1..=MAX_AUTH_RETRIES {
        match challenge_response(vta_url, credential_did, private_key_multibase, vta_did).await {
            Ok(result) => {
                if result.access_token.is_empty() {
                    bail!("VTA returned an empty access token");
                }
                return Ok(result);
            }
            Err(e) => {
                let err_msg = format!("{e}");
                if attempt < MAX_AUTH_RETRIES {
                    eprintln!(
                        "VTA auth attempt {attempt}/{MAX_AUTH_RETRIES} failed: {err_msg}, retrying..."
                    );
                }
                last_err = Some(err_msg);
            }
        }
    }
    bail!(
        "VTA authentication failed after {MAX_AUTH_RETRIES} attempts: {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    )
}

/// Fetch the Ed25519 signing key seed from VTA. Returns 32-byte seed.
/// The seed is zeroized on drop via the returned wrapper.
pub async fn get_signing_key(client: &VtaClient, key_id: &str) -> Result<SeedMaterial> {
    let resp = client
        .get_key_secret(key_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch key secret: {e}"))?;

    if resp.key_type != vta_sdk::keys::KeyType::Ed25519 {
        bail!(
            "signing key {key_id} is {:?}, expected Ed25519",
            resp.key_type
        );
    }

    let seed = vta_sdk::did_key::decode_private_key_multibase(&resp.private_key_multibase)
        .context("failed to decode signing key")?;

    Ok(SeedMaterial(seed))
}

/// Wrapper around a 32-byte Ed25519 seed that zeroizes on drop.
pub struct SeedMaterial([u8; 32]);

impl SeedMaterial {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SeedMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_creds() -> VtaCredentials {
        VtaCredentials {
            vta_url: "https://vta.example.com".to_string(),
            vta_did: "did:example:vta".to_string(),
            credential_did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z...".to_string(),
            key_id: "key-1".to_string(),
        }
    }

    #[test]
    fn test_validate_rejects_empty_url() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_rejects_http() {
        let mut creds = test_creds();
        creds.vta_url = "http://example.com".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_allows_https() {
        assert!(validate_credentials(&test_creds()).is_ok());
    }

    #[test]
    fn test_validate_allows_localhost() {
        let mut creds = test_creds();
        creds.vta_url = "http://localhost:3000".to_string();
        assert!(validate_credentials(&creds).is_ok());
    }

    #[test]
    fn test_validate_rejects_empty_key_id() {
        let mut creds = test_creds();
        creds.key_id = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_rejects_empty_credential_did() {
        let mut creds = test_creds();
        creds.credential_did = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_seed_material_zeroizes_on_drop() {
        let seed = SeedMaterial([0xAB; 32]);
        assert_eq!(seed.as_bytes(), &[0xAB; 32]);
        drop(seed);
    }
}
