//! Settings action handlers for the TUI.

use anyhow::Result;
use openvtc::{config::Config, logs::LogFamily};
use secrecy::SecretString;
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

/// Export the config to a file, encrypted with the given passphrase.
pub fn export_config(config: &Config, path: &str, passphrase: &str) -> Result<()> {
    let secret = SecretString::new(passphrase.to_string().into());
    config.export(Some(secret), path)?;
    info!(path = %path, "config exported");
    Ok(())
}
