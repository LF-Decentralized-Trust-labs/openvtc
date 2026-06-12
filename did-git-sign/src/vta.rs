use anyhow::{Context, Result, bail};
use vta_sdk::client::{AutoConnect, ConnectedVta, VtaClient};
use zeroize::Zeroize;

use crate::config::{self, SigningConfig, VtaCredentials};

/// Maximum number of authentication retry attempts.
const MAX_AUTH_RETRIES: u32 = 2;

/// Authenticate with VTA, using whichever transport the install captured.
/// Returns an authenticated `VtaClient` and the loaded VTA credentials.
///
/// - **DIDComm transport** (`mediator_did` is `Some`) — opens a fresh
///   DIDComm session as the credential DID against the advertised
///   mediator. The session itself is the authenticator; there is no
///   bearer token to cache, so the keyring token cache is bypassed on
///   this path.
/// - **REST transport** (`mediator_did` is `None`) — original behaviour:
///   try cached token first, fall back to challenge-response auth with
///   retry, cache the new token for next time.
pub async fn authenticate(cfg: &SigningConfig) -> Result<(VtaClient, VtaCredentials)> {
    let creds = config::load_vta_credentials(&cfg.did_key_id)?;
    validate_credentials(&creds)?;

    // REST transport with a cached bearer token: short-circuit the handshake.
    // Token caching stays caller-side — the SDK deliberately leaves it to us.
    if creds.mediator_did.is_none()
        && let Some(token) = config::load_cached_token(&cfg.did_key_id)
    {
        let client = VtaClient::new(&creds.vta_url);
        client.set_token(token);
        return Ok((client, creds));
    }

    // Let the SDK pick the transport and run the handshake. `connect_auto`
    // encapsulates the DIDComm-vs-REST branch, the `rest_fallback` derivation,
    // and the empty-URL rule we used to hand-roll here and in openvtc-core —
    // that logic is SDK-level knowledge, so it lives there now (R22). We keep
    // the transient-failure retry and (REST) token caching, both of which are
    // application policy.
    let connected = connect_with_retry(&creds).await?;

    // DIDComm sessions carry no bearer token (`rest_token` is `None`); a REST
    // handshake issues one, which we cache for the next invocation.
    if let Some(token) = &connected.rest_token {
        let _ = config::cache_token(
            &cfg.did_key_id,
            &token.access_token,
            token.access_expires_at,
        );
    }

    Ok((connected.client, creds))
}

/// Validate VTA credentials before use.
///
/// REST transport requires a non-empty HTTPS URL. DIDComm transport
/// (`mediator_did` set) treats `vta_url` as optional — an empty value is
/// fine for VTAs that publish no `#vta-rest` service at all.
fn validate_credentials(creds: &VtaCredentials) -> Result<()> {
    if creds.credential_did.is_empty() {
        bail!("credential DID is empty");
    }
    if creds.key_id.is_empty() {
        bail!("signing key ID is empty");
    }

    if creds.mediator_did.is_some() {
        // DIDComm transport — the URL is optional. If it *is* set, hold
        // it to the same HTTPS rule (it'll be passed through as a /health
        // fallback so we don't want to risk leaking creds over plain HTTP).
        if !creds.vta_url.is_empty()
            && !creds.vta_url.starts_with("https://")
            && !creds.vta_url.starts_with("http://localhost")
        {
            bail!(
                "VTA URL must use HTTPS (got: {}). Use http://localhost only for local development.",
                creds.vta_url
            );
        }
        return Ok(());
    }

    // REST transport — URL is required.
    if creds.vta_url.is_empty() {
        bail!("VTA URL is empty");
    }
    if !creds.vta_url.starts_with("https://") && !creds.vta_url.starts_with("http://localhost") {
        bail!(
            "VTA URL must use HTTPS (got: {}). Use http://localhost only for local development.",
            creds.vta_url
        );
    }
    Ok(())
}

/// Connect via [`VtaClient::connect_auto`] with retry on transient failures.
///
/// The transport (DIDComm vs REST) is chosen by the SDK from `creds`. Retry
/// covers both paths uniformly — a transient mediator or network hiccup is
/// worth a second attempt regardless of transport.
async fn connect_with_retry(creds: &VtaCredentials) -> Result<ConnectedVta> {
    let mut last_err = None;
    for attempt in 1..=MAX_AUTH_RETRIES {
        let result = VtaClient::connect_auto(AutoConnect {
            vta_url: &creds.vta_url,
            vta_did: &creds.vta_did,
            credential_did: &creds.credential_did,
            private_key_multibase: &creds.private_key_multibase,
            mediator_did: creds.mediator_did.as_deref(),
        })
        .await;
        match result {
            Ok(connected) => {
                // A REST handshake must yield a non-empty bearer token; DIDComm
                // carries none (`rest_token` is `None`), so this skips it.
                if let Some(token) = &connected.rest_token
                    && token.access_token.is_empty()
                {
                    bail!("VTA returned an empty access token");
                }
                return Ok(connected);
            }
            Err(e) => {
                let err_msg = format!("{e}");
                if attempt < MAX_AUTH_RETRIES {
                    eprintln!(
                        "VTA connect attempt {attempt}/{MAX_AUTH_RETRIES} failed: {err_msg}, retrying..."
                    );
                }
                last_err = Some(err_msg);
            }
        }
    }
    bail!(
        "VTA connection failed after {MAX_AUTH_RETRIES} attempts: {}",
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
            mediator_did: None,
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

    #[test]
    fn test_validate_didcomm_only_accepts_empty_url() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        assert!(validate_credentials(&creds).is_ok());
    }

    #[test]
    fn test_validate_didcomm_with_url_still_requires_https() {
        let mut creds = test_creds();
        creds.vta_url = "http://example.com".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_didcomm_still_rejects_empty_credential_did() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        creds.credential_did = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }
}
