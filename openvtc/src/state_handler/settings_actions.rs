//! Settings action handlers for the TUI.

use anyhow::Result;
use openvtc_core::{config::Config, logs::LogFamily};
use secrecy::{SecretBox, SecretString};
use tracing::info;

/// Save the config to disk using the profile name.
pub fn save_config(config: &Config, profile: &str) -> Result<()> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {},
    )?;
    Ok(())
}

/// Update the friendly name and save.
pub fn update_friendly_name(config: &mut Config, profile: &str, name: &str) -> Result<()> {
    config.public.friendly_name = name.to_string();
    config.public.logs.insert(
        LogFamily::Config,
        format!("Friendly name changed to '{}'", name),
    );
    save_config(config, profile)?;
    info!(name = %name, "friendly name updated");
    Ok(())
}

/// Update the mediator DID and save.
pub fn update_mediator_did(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config.public.mediator_did = did.to_string();
    config.public.logs.insert(
        LogFamily::Config,
        format!("Mediator DID changed to '{}'", did),
    );
    save_config(config, profile)?;
    info!(did = %did, "mediator DID updated (reconnect needed)");
    Ok(())
}

/// Update the organization DID and save.
pub fn update_org_did(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config.public.lk_did = did.to_string();
    config
        .public
        .logs
        .insert(LogFamily::Config, format!("Org DID changed to '{}'", did));
    save_config(config, profile)?;
    info!(did = %did, "org DID updated");
    Ok(())
}

/// Set a passphrase to encrypt the config in the keyring.
pub fn set_passphrase(config: &mut Config, profile: &str, passphrase: &str) -> Result<()> {
    use openvtc_core::config::{ConfigProtectionType, derive_passphrase_key, validate_passphrase};

    validate_passphrase(passphrase)?;
    let key = derive_passphrase_key(passphrase.as_bytes(), b"openvtc-unlock-code-v1")?;
    config.unlock_code = Some(SecretBox::new(Box::new(key.to_vec())));
    config.public.protection = ConfigProtectionType::Encrypted;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to passphrase encrypted".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection set to passphrase encrypted");
    Ok(())
}

/// Remove passphrase protection, reverting to keyring-only.
pub fn remove_passphrase(config: &mut Config, profile: &str) -> Result<()> {
    use openvtc_core::config::ConfigProtectionType;

    config.unlock_code = None;
    config.public.protection = ConfigProtectionType::Plaintext;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to keyring only (no additional encryption)".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection reverted to keyring only");
    Ok(())
}

/// Validate a file path for export/import operations.
fn validate_file_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        anyhow::bail!("File path cannot be empty");
    }
    if path.contains("..") {
        anyhow::bail!("Path traversal (..) is not allowed");
    }
    Ok(())
}

/// Export the config to a file, encrypted with the given passphrase.
pub fn export_config(config: &Config, path: &str, passphrase: &str) -> Result<()> {
    validate_file_path(path)?;
    let secret = SecretString::new(passphrase.to_string().into());
    config.export(Some(secret), path)?;
    info!(path = %path, "config exported");
    Ok(())
}

/// Import a config from file. Currently only validates and advises restart.
pub fn import_config(path: &str, _passphrase: &str) -> Result<String> {
    validate_file_path(path)?;
    // Validate the file exists
    if !std::path::Path::new(path).exists() {
        anyhow::bail!("File not found: {}", path);
    }
    // Full implementation would load ExportedConfig, decrypt, and replace
    Ok(format!(
        "Import from {} would require app restart — use openvtc setup import",
        path
    ))
}

/// Add a contact by DID with an optional alias (synchronous, no DID resolution).
pub fn add_contact(
    config: &mut Config,
    profile: &str,
    did: &str,
    alias: Option<&str>,
) -> Result<()> {
    use openvtc_core::config::protected_config::Contact;
    use std::sync::Arc;

    let contact_did = Arc::new(did.to_string());
    let alias_str = alias.map(|a| a.to_string());
    let contact = Arc::new(Contact {
        did: contact_did.clone(),
        alias: alias_str.clone(),
    });

    config
        .private
        .contacts
        .contacts
        .insert(contact_did, contact.clone());

    if let Some(a) = &alias_str {
        config.private.contacts.aliases.insert(a.clone(), contact);
    }

    config.public.logs.insert(
        LogFamily::Config,
        format!("Contact added: {} alias({})", did, alias.unwrap_or("N/A")),
    );
    save_config(config, profile)?;
    info!(did = %did, "contact added");
    Ok(())
}

/// Remove a contact by DID.
pub fn remove_contact(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, did);
    save_config(config, profile)?;
    info!(did = %did, "contact removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path_rejects_empty() {
        assert!(validate_file_path("").is_err());
        assert!(validate_file_path("   ").is_err());
    }

    #[test]
    fn test_validate_file_path_rejects_traversal() {
        assert!(validate_file_path("../../etc/passwd").is_err());
        assert!(validate_file_path("foo/../bar").is_err());
    }

    #[test]
    fn test_validate_file_path_accepts_normal() {
        assert!(validate_file_path("export.enc").is_ok());
        assert!(validate_file_path("/home/user/backup.enc").is_ok());
    }

    #[test]
    fn test_validate_file_path_accepts_dot_slash() {
        assert!(validate_file_path("./local-file.dat").is_ok());
    }

    #[test]
    fn test_validate_file_path_rejects_hidden_traversal() {
        assert!(validate_file_path("/tmp/safe/../../../etc/shadow").is_err());
    }
}
