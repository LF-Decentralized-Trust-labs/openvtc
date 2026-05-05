use affinidi_tdk::{
    did_common::{
        Document,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    secrets_resolver::secrets::Secret,
};
use didwebvh_rs::{
    DIDWebVHError,
    create::{CreateDIDConfig, create_did},
    log_entry::LogEntryMethods,
    parameters::Parameters,
    url::WebVHURL,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

use crate::{config::PersonaDIDKeys, errors::OpenVTCError};

/// Creates a new `did:webvh` DID with key pre-rotation enabled.
///
/// This builds a full DID Document containing three verification methods:
/// - `#key-1` (Ed25519) -- assertion method (signing)
/// - `#key-2` (Ed25519) -- authentication
/// - `#key-3` (X25519) -- key agreement (encryption)
///
/// A DIDComm messaging service endpoint pointing to the given `mediator_did` is
/// also added to the document.
///
/// # Parameters
/// - `raw_url`: The WebVH server URL where the DID log will be hosted (e.g. `https://fpp.storm.ws`).
/// - `keys`: Mutable persona keys whose secret IDs are updated to match the created DID.
/// - `mediator_did`: The DID of the mediator used as the DIDComm service endpoint.
/// - `update_secret`: The Ed25519 secret used to authorize this initial DID log entry.
/// - `next_update_secret`: The Ed25519 secret whose hash is committed for key pre-rotation.
/// - `did_log_path`: Where to write the resulting DID log (`did.jsonl`). Should
///   be inside the active profile directory — see [`crate::config::public_config::profile_dir`].
///
/// # Returns
/// A tuple of `(did_id, Document)` where `did_id` is the fully-qualified `did:webvh:...`
/// string and `Document` is the resolved DID Document produced by the creation process.
pub async fn create_initial_webvh_did(
    raw_url: &str,
    keys: &mut PersonaDIDKeys,
    mediator_did: &str,
    update_secret: Secret,
    next_update_secret: Secret,
    did_log_path: &Path,
) -> Result<(String, Document), OpenVTCError> {
    // Normalize and validate the URL, then derive the placeholder DID using
    // the didwebvh-rs library so that URL path components (e.g. "/custom/path")
    // are correctly converted to colon-separated DID path segments
    // (e.g. "did:webvh:{SCID}:example.com:custom:path") rather than leaving a
    // stray slash that produces an invalid DID like
    // "did:webvh:{SCID}:example.com/custom/path".
    let normalized_url = normalize_webvh_url(raw_url)?;
    let parsed_url = Url::parse(&normalized_url)
        .map_err(|e| OpenVTCError::Config(format!("Invalid URL ({normalized_url}): {e}")))?;
    let webvh_url = WebVHURL::parse_url(&parsed_url)
        .map_err(|e| OpenVTCError::Config(format!("Invalid WebVH URL: {e}")))?;
    let placeholder_did = webvh_url.to_did_base();
    let mut did_document = Document::new(&placeholder_did)
        .map_err(|e| OpenVTCError::Config(format!("Invalid DID URL: {e}")))?;

    // Add the verification methods to the DID Document
    let mut property_set: HashMap<String, Value> = HashMap::new();

    // Signing Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(keys.signing.secret.get_public_keymultibase().map_err(|e| {
            DIDWebVHError::InvalidMethodIdentifier(format!(
                "Couldn't set signing verificationMethod publicKeybase: {e}"
            ))
        })?),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-1"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod Key ID for #key-1: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .assertion_method
        .push(VerificationRelationship::Reference(key_id.to_string()));

    // Authentication Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(
            keys.authentication
                .secret
                .get_public_keymultibase()
                .map_err(|e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "Couldn't set authentication verificationMethod publicKeybase: {e}"
                    ))
                })?,
        ),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-2"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod key ID for #key-2: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .authentication
        .push(VerificationRelationship::Reference(key_id.to_string()));

    // Decryption Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(
            keys.decryption
                .secret
                .get_public_keymultibase()
                .map_err(|e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "Couldn't set decryption verificationMethod publicKeybase: {e}"
                    ))
                })?,
        ),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-3"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod key ID for #key-3: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .key_agreement
        .push(VerificationRelationship::Reference(key_id.to_string()));

    // Add a service endpoint for this persona
    let endpoint = Endpoint::Map(json!([{"accept": ["didcomm/v2"], "uri": mediator_did}]));
    did_document.service.push(Service {
        id: Some(
            Url::parse(&[&placeholder_did, "#public-didcomm"].concat()).map_err(|e| {
                DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't set Service Endpoint for #public-didcomm: {e}"
                ))
            })?,
        ),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: HashMap::new(),
        service_endpoint: endpoint,
    });

    // Prepare the update secret with proper did:key ID
    let mut update_secret = update_secret;
    update_secret.id = [
        "did:key:",
        &update_secret.get_public_keymultibase().map_err(|e| {
            OpenVTCError::Secret(format!(
                "update Secret Key was missing public key information! {e}"
            ))
        })?,
        "#",
        &update_secret.get_public_keymultibase().map_err(|e| {
            OpenVTCError::Secret(format!(
                "update Secret Key was missing public key information! {e}"
            ))
        })?,
    ]
    .concat();

    let parameters = Parameters::new()
        .with_key_pre_rotation(true)
        .with_update_keys(vec![update_secret.get_public_keymultibase().map_err(
            |e| {
                OpenVTCError::Secret(format!(
                    "update Secret Key was missing public key information! {e}"
                ))
            },
        )?])
        .with_next_key_hashes(vec![
            next_update_secret
                .get_public_keymultibase_hash()
                .map_err(|e| {
                    OpenVTCError::Secret(format!(
                        "next_update Secret Key was missing public key information! {e}"
                    ))
                })?,
        ])
        .with_portable(true)
        .build();

    // Use the new create_did API
    let config = CreateDIDConfig::builder()
        .address(&normalized_url)
        .authorization_key(update_secret)
        .did_document(serde_json::to_value(&did_document)?)
        .parameters(parameters)
        .build()?;

    let result = create_did(config).await?;

    let did_id = result.did();

    // Change the key ID's to match the DID VM ID's
    keys.signing.secret.id = [did_id, "#key-1"].concat();
    keys.authentication.secret.id = [did_id, "#key-2"].concat();
    keys.decryption.secret.id = [did_id, "#key-3"].concat();

    // Persist the DID log alongside the active profile config. didwebvh-rs
    // truncates on the v1 entry and appends thereafter — the path is the
    // caller's contract; we just ensure the parent directory exists.
    if let Some(parent) = did_log_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            OpenVTCError::Config(format!(
                "couldn't create DID log directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    let did_log_path_str = did_log_path
        .to_str()
        .ok_or_else(|| OpenVTCError::Config("DID log path contains invalid UTF-8".to_string()))?;
    result.log_entry().save_to_file(did_log_path_str)?;

    Ok((
        did_id.to_string(),
        serde_json::from_value(result.log_entry().get_did_document()?)?,
    ))
}

/// Normalize a user-supplied WebVH URL into a form acceptable to didwebvh-rs.
///
/// Accepts input like `example.com`, `example.com/path`, `https://example.com`,
/// or `https://example.com/path/` and returns a canonicalized
/// `https://host[:port]/path/` string (trailing slash present). Rejects
/// malformed inputs early so the user gets a clear error rather than a
/// silently-broken DID.
///
/// Rejection rules:
/// - schemes other than `http` / `https`
/// - missing or empty host
/// - empty-segment paths (e.g. `example.com//foo`, `example.com/foo//bar`)
///   which would turn into consecutive colons in the DID
/// - path segments containing `:` or whitespace (would corrupt the DID)
/// - any query or fragment (not supported in a persona DID address)
pub fn normalize_webvh_url(raw_url: &str) -> Result<String, OpenVTCError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(OpenVTCError::Config(
            "WebVH URL is empty. Expected e.g. https://example.com or https://example.com/path"
                .to_string(),
        ));
    }

    // If the user supplied an explicit scheme, keep it; only http/https are allowed.
    // Otherwise default to https. We detect "scheme://" via `://` so that schemes
    // other than http/https are caught here rather than being silently converted.
    let with_scheme = if let Some(scheme_end) = trimmed.find("://") {
        let scheme = &trimmed[..scheme_end];
        if scheme != "http" && scheme != "https" {
            return Err(OpenVTCError::Config(format!(
                "WebVH URL must use http or https (got {scheme}://)"
            )));
        }
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    // Guard against empty path segments (e.g. "example.com//foo") *before*
    // letting `url::Url` normalize them away. After stripping the scheme,
    // any `//` in the remainder implies an empty path segment.
    let after_scheme = with_scheme
        .strip_prefix("https://")
        .or_else(|| with_scheme.strip_prefix("http://"))
        .unwrap_or(with_scheme.as_str());
    if after_scheme.contains("//") {
        return Err(OpenVTCError::Config(format!(
            "WebVH URL path contains an empty segment (consecutive slashes): {raw_url}"
        )));
    }

    let url = Url::parse(&with_scheme)
        .map_err(|e| OpenVTCError::Config(format!("Invalid URL ({raw_url}): {e}")))?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(OpenVTCError::Config(format!(
            "WebVH URL must use http or https (got {}://)",
            url.scheme()
        )));
    }
    if url.host_str().is_none_or(|h| h.is_empty()) {
        return Err(OpenVTCError::Config(format!(
            "WebVH URL is missing a host: {raw_url}"
        )));
    }
    if url.query().is_some() {
        return Err(OpenVTCError::Config(format!(
            "WebVH URL must not contain a query string: {raw_url}"
        )));
    }
    if url.fragment().is_some() {
        return Err(OpenVTCError::Config(format!(
            "WebVH URL must not contain a fragment: {raw_url}"
        )));
    }

    // Validate path segments: empty segments (from `//`) and segments
    // containing `:` or whitespace would produce a malformed DID.
    let path = url.path();
    let stripped = path.trim_start_matches('/').trim_end_matches('/');
    if !stripped.is_empty() {
        for segment in stripped.split('/') {
            if segment.is_empty() {
                return Err(OpenVTCError::Config(format!(
                    "WebVH URL path contains an empty segment (consecutive slashes): {raw_url}"
                )));
            }
            if segment.contains(':') || segment.chars().any(|c| c.is_whitespace()) {
                return Err(OpenVTCError::Config(format!(
                    "WebVH URL path segment '{segment}' contains invalid characters \
                     (':' or whitespace): {raw_url}"
                )));
            }
        }
    }

    // Re-emit a canonical form with a trailing slash on the path so the
    // didwebvh-rs URL parser treats the path uniformly.
    let host = url.host_str().unwrap();
    let scheme = url.scheme();
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    if stripped.is_empty() {
        out.push('/');
    } else {
        out.push('/');
        out.push_str(stripped);
        out.push('/');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder_did_for(raw_url: &str) -> String {
        let normalized = normalize_webvh_url(raw_url).expect("normalize");
        let parsed = Url::parse(&normalized).expect("parse url");
        let webvh = WebVHURL::parse_url(&parsed).expect("webvh parse");
        webvh.to_did_base()
    }

    #[test]
    fn normalize_adds_https_when_missing() {
        assert_eq!(
            normalize_webvh_url("example.com").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn normalize_preserves_explicit_scheme_and_port() {
        assert_eq!(
            normalize_webvh_url("http://localhost:8080/path").unwrap(),
            "http://localhost:8080/path/"
        );
    }

    #[test]
    fn normalize_adds_trailing_slash() {
        assert_eq!(
            normalize_webvh_url("https://example.com/vincent").unwrap(),
            "https://example.com/vincent/"
        );
    }

    #[test]
    fn normalize_collapses_leading_slash_only_paths() {
        assert_eq!(
            normalize_webvh_url("https://example.com/").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(normalize_webvh_url("   ").is_err());
    }

    #[test]
    fn normalize_rejects_double_slash_path() {
        let err = normalize_webvh_url("https://example.com//vincent").unwrap_err();
        assert!(err.to_string().contains("empty segment"), "got: {err}");
    }

    #[test]
    fn normalize_rejects_non_http_scheme() {
        assert!(normalize_webvh_url("ftp://example.com/").is_err());
    }

    #[test]
    fn normalize_rejects_query_and_fragment() {
        assert!(normalize_webvh_url("https://example.com/?x=1").is_err());
        assert!(normalize_webvh_url("https://example.com/#frag").is_err());
    }

    #[test]
    fn normalize_rejects_colon_in_path_segment() {
        assert!(normalize_webvh_url("https://example.com/foo:bar").is_err());
    }

    /// Regression: https://r2.ic3.dev/vincent previously produced a placeholder
    /// DID with a stray slash ("did:webvh:{SCID}:r2.ic3.dev/vincent") which
    /// resolved to "r2.ic3.dev/vincent/.well-known/did.jsonl". The DID should
    /// use colons between the host and path components.
    #[test]
    fn placeholder_did_converts_path_slash_to_colon() {
        assert_eq!(
            placeholder_did_for("https://r2.ic3.dev/vincent"),
            "did:webvh:{SCID}:r2.ic3.dev:vincent"
        );
    }

    #[test]
    fn placeholder_did_handles_multiple_path_segments() {
        assert_eq!(
            placeholder_did_for("https://example.com/foo/bar"),
            "did:webvh:{SCID}:example.com:foo:bar"
        );
    }

    #[test]
    fn placeholder_did_handles_no_path() {
        assert_eq!(
            placeholder_did_for("https://example.com/"),
            "did:webvh:{SCID}:example.com"
        );
    }

    #[test]
    fn placeholder_did_encodes_port() {
        assert_eq!(
            placeholder_did_for("http://localhost:8080/test"),
            "did:webvh:{SCID}:localhost%3A8080:test"
        );
    }
}
