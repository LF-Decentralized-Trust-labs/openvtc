mod config;
mod init;
mod sign;
mod vta;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dialoguer::{Select, theme::ColorfulTheme};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

use config::{SigningConfig, VtaCredentials};

#[derive(Parser)]
#[command(
    name = "did-git-sign",
    about = "Git commit signing using DID Ed25519 keys via VTA",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// SSH-keygen compatibility: operation flag (e.g., -Y sign)
    #[arg(short = 'Y', hide = true)]
    operation: Option<String>,

    /// SSH-keygen compatibility: key/config file path
    #[arg(short = 'f', hide = true)]
    key_file: Option<PathBuf>,

    /// SSH-keygen compatibility: namespace
    #[arg(short = 'n', hide = true)]
    namespace: Option<String>,

    /// SSH-keygen compatibility: file to sign (positional, passed by git)
    #[arg(hide = true)]
    sign_file: Option<PathBuf>,

    /// SSH-keygen compatibility: signature file (-s <file>, used by -Y verify)
    #[arg(short = 's', hide = true)]
    sig_file: Option<PathBuf>,

    /// SSH-keygen compatibility: signer identity (-I <principal>, used by -Y verify)
    #[arg(short = 'I', hide = true)]
    identity: Option<String>,

    /// SSH-keygen compatibility: signature option (-O <option>, used by -Y verify, repeatable)
    #[arg(short = 'O', hide = true, action = clap::ArgAction::Append)]
    sig_option: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize git configuration for DID-based signing
    Init {
        /// Use global git config instead of repo-local
        #[arg(long)]
        global: bool,

        /// Base64url-encoded VTA credential bundle
        #[arg(long)]
        credential: String,

        /// Git user.name to set
        #[arg(long)]
        name: Option<String>,

        /// VTA URL (overrides credential bundle)
        #[arg(long)]
        vta_url: Option<String>,

        /// VTA key ID for the signing key (skip interactive selection)
        #[arg(long)]
        key_id: Option<String>,

        /// DID#key-id to use as signing identity (skip interactive selection)
        #[arg(long)]
        did_key_id: Option<String>,
    },

    /// Verify the signing setup by performing a test sign operation
    Verify,

    /// Check configuration, VTA connectivity, and show signing public key
    Health,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Handle SSH-keygen-compatible invocation:
    // git calls: did-git-sign -Y sign -f <config> -n <namespace> <file_to_sign>
    if let Some(op) = &cli.operation {
        match op.as_str() {
            "sign" => {
                let config_path = cli
                    .key_file
                    .as_ref()
                    .context("missing -f <config_path> argument")?;
                let namespace = cli.namespace.as_deref().unwrap_or("git");
                return sign::handle_sign(config_path, namespace, cli.sign_file.as_deref()).await;
            }
            _ => {
                // All other -Y operations (verify, find-principals, check-novalidate,
                // and any future operations git may introduce) are forwarded verbatim
                // to ssh-keygen. did-git-sign only intercepts signing — everything else
                // requires no VTA authentication and is handled natively by ssh-keygen.
                let code = delegate_to_ssh_keygen(op, &cli)?;
                // NOTE: process::exit skips tokio runtime shutdown. Safe here because no
                // async work is performed in this branch after delegation. If async work
                // is ever added above this line, switch to a clean return from main instead.
                std::process::exit(code);
            }
        }
    }

    match cli.command {
        Some(Commands::Init {
            global,
            credential,
            name,
            vta_url,
            key_id,
            did_key_id,
        }) => cmd_init(global, &credential, name, vta_url, key_id, did_key_id).await,
        Some(Commands::Verify) => cmd_verify().await,
        Some(Commands::Health) => cmd_health().await,
        None => {
            // sign_file is only legitimate when -Y sign is set (git signing invocation).
            // If it is set without -Y, the user typed an unrecognised subcommand.
            // Without this guard, typos like `did-git-sign verfy` silently fall through to help.
            if let Some(f) = &cli.sign_file {
                if cli.operation.is_none() {
                    anyhow::bail!(
                        "unrecognised subcommand {:?}\n\nUsage: did-git-sign [COMMAND]\n\nRun 'did-git-sign --help' for available commands.",
                        f.display()
                    );
                }
            }
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

async fn cmd_init(
    global: bool,
    credential_b64: &str,
    user_name: Option<String>,
    vta_url_override: Option<String>,
    key_id_override: Option<String>,
    did_key_id_override: Option<String>,
) -> Result<()> {
    // Decode credential bundle
    let bundle = vta_sdk::credentials::CredentialBundle::decode(credential_b64)
        .map_err(|e| anyhow::anyhow!("failed to decode credential bundle: {e:?}"))?;

    let vta_url = vta_url_override
        .or(bundle.vta_url.clone())
        .context("VTA URL not found in credential bundle — provide --vta-url")?;

    // Authenticate with VTA
    println!("Authenticating with VTA at {vta_url}...");
    let client = vta_sdk::client::VtaClient::new(&vta_url);
    let token = vta_sdk::session::challenge_response(
        &vta_url,
        &bundle.did,
        &bundle.private_key_multibase,
        &bundle.vta_did,
    )
    .await
    .map_err(|e| anyhow::anyhow!("VTA authentication failed: {e}"))?;
    client.set_token(token.access_token.clone());
    println!("Authenticated.");
    println!();

    let (key_id, did_key_id) =
        if let (Some(kid), Some(dkid)) = (key_id_override, did_key_id_override) {
            // Non-interactive: use provided values directly
            (kid, dkid)
        } else {
            // Interactive: select context, DID, and signing key
            interactive_select(&client).await?
        };

    // Config file contains only the DID identity
    let cfg = SigningConfig {
        did_key_id: did_key_id.clone(),
        user_name,
    };

    // VTA credentials and key ID go into the OS keyring
    let vta_creds = VtaCredentials {
        vta_url,
        vta_did: bundle.vta_did.clone(),
        credential_did: bundle.did.clone(),
        private_key_multibase: bundle.private_key_multibase.clone(),
        key_id,
    };

    // Determine config path
    let config_path = if global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };

    // Save config (non-sensitive only)
    cfg.save(&config_path)?;
    println!("Config saved to: {}", config_path.display());

    // Store VTA credentials in keyring
    config::store_vta_credentials(&did_key_id, &vta_creds)?;
    println!("VTA credentials stored in OS keyring");

    // Cache the token we already have
    let _ = config::cache_token(&did_key_id, &token.access_token, token.access_expires_at);

    // Fetch signing key to get public key for allowed_signers
    let (auth_client, creds) = vta::authenticate(&cfg).await?;
    let seed = vta::get_signing_key(&auth_client, &creds.key_id).await?;
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();

    // Configure git
    init::setup_git(&config_path, &cfg, global)?;
    println!("Git configured for DID signing");

    // Detect if a global user.signingKey was overridden by our local init.
    // Print a notice so the user is not surprised when inspecting git config --list.
    let global_signing_key = std::process::Command::new("git")
        .args(["config", "--global", "user.signingKey"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(prev) = global_signing_key {
        println!();
        println!("Note: your global user.signingKey ({prev}) has been overridden locally");
        println!("      for this repository. did-git-sign uses its JSON config file as the");
        println!("      signing key path. Your global signing configuration is unchanged.");
    }

    // Set up allowed_signers for verification
    let entry = init::allowed_signers_entry(&cfg, verifying_key.as_bytes());
    let config_dir = config_path.parent().unwrap_or(std::path::Path::new("."));
    init::setup_allowed_signers(config_dir, &entry, global)?;
    println!("Allowed signers file updated");

    println!();
    println!("Setup complete! Git commits will now be signed with:");
    println!("  DID: {did_key_id}");
    println!(
        "  Key: ssh-ed25519 {}",
        init::ssh_public_key_string(verifying_key.as_bytes())
    );
    println!();
    println!("IMPORTANT — to make signatures show as 'Verified':");
    println!("  1. Copy the SSH public key above.");
    println!("  2. Add it to your account:");
    println!("       User Settings → SSH Keys → Add new key");
    println!("       Set Usage type to 'Signing' (or 'Authentication & Signing').");
    println!("  3. Ensure git user.email matches your account email:");
    println!("       git config user.email");
    println!();
    println!("To sign a commit: git commit -S -m \"your message\"");
    println!("To verify: git log --show-signature");

    Ok(())
}

/// Interactive flow: select context → DID → signing key.
/// Returns (vta_key_id, did_key_id).
async fn interactive_select(client: &vta_sdk::client::VtaClient) -> Result<(String, String)> {
    // 1. List and select context
    let contexts = client
        .list_contexts()
        .await
        .map_err(|e| anyhow::anyhow!("failed to list contexts: {e}"))?;

    if contexts.contexts.is_empty() {
        bail!("no contexts found in VTA — create a context first");
    }

    let context_labels: Vec<String> = contexts
        .contexts
        .iter()
        .map(|c| {
            let did_info = c.did.as_deref().unwrap_or("no DID");
            format!("{} — {} ({})", c.id, c.name, did_info)
        })
        .collect();

    let ctx_idx = if contexts.contexts.len() == 1 {
        println!("Using context: {}", context_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a context")
            .items(&context_labels)
            .default(0)
            .interact()?
    };
    let context = &contexts.contexts[ctx_idx];
    println!();

    // 2. List and select DID in this context
    let dids = client
        .list_dids_webvh(Some(&context.id), None)
        .await
        .map_err(|e| anyhow::anyhow!("failed to list DIDs: {e}"))?;

    if dids.dids.is_empty() {
        bail!(
            "no DIDs found in context '{}' — create a DID first",
            context.id
        );
    }

    let did_labels: Vec<String> = dids.dids.iter().map(|d| d.did.clone()).collect();

    let did_idx = if dids.dids.len() == 1 {
        println!("Using DID: {}", did_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a DID")
            .items(&did_labels)
            .default(0)
            .interact()?
    };
    let selected_did = &dids.dids[did_idx].did;
    println!();

    // 3. List Ed25519 keys in this context
    let keys = client
        .list_keys(0, 100, Some("active"), Some(&context.id))
        .await
        .map_err(|e| anyhow::anyhow!("failed to list keys: {e}"))?;

    let ed25519_keys: Vec<_> = keys
        .keys
        .iter()
        .filter(|k| k.key_type == vta_sdk::keys::KeyType::Ed25519)
        .collect();

    if ed25519_keys.is_empty() {
        bail!(
            "no active Ed25519 keys found in context '{}' — create signing keys first",
            context.id
        );
    }

    let key_labels: Vec<String> = ed25519_keys
        .iter()
        .map(|k| {
            let label = k.label.as_deref().unwrap_or("unlabeled");
            format!("{} ({})", label, k.key_id)
        })
        .collect();

    let key_idx = if ed25519_keys.len() == 1 {
        println!("Using key: {}", key_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a signing key")
            .items(&key_labels)
            .default(0)
            .interact()?
    };
    let selected_key = ed25519_keys[key_idx];
    println!();

    // 4. Determine the DID#key-id by matching the key's public key against
    //    the DID document's verification methods
    let did_key_id = resolve_did_key_fragment(client, selected_did, selected_key).await?;

    println!("Signing identity: {did_key_id}");
    println!();

    Ok((selected_key.key_id.clone(), did_key_id))
}

/// Match a VTA key's public key against a DID document's verification methods
/// to find the corresponding DID#key-N fragment.
async fn resolve_did_key_fragment(
    client: &vta_sdk::client::VtaClient,
    did: &str,
    key: &vta_sdk::keys::KeyRecord,
) -> Result<String> {
    // Try to get the DID document from VTA
    let _did_record = client
        .get_did_webvh(did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get DID record: {e}"))?;

    // Try to get the DID log to extract the document
    let log_resp = client
        .get_did_webvh_log(did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get DID log: {e}"))?;

    if let Some(log) = &log_resp.log
        && let Some(last_line) = log.lines().last()
        && let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line)
        && let Some(state) = entry.get("state")
        && let Some(vms) = state.get("verificationMethod")
        && let Some(vms_arr) = vms.as_array()
    {
        for vm in vms_arr {
            if let Some(pub_key_mb) = vm.get("publicKeyMultibase")
                && pub_key_mb.as_str() == Some(&key.public_key)
                && let Some(id) = vm.get("id").and_then(|v| v.as_str())
            {
                return Ok(id.to_string());
            }
        }
    }

    // Fallback: if we can't match, use the DID + #key-0 convention
    // (the first signing key is typically #key-0 for VTA-created DIDs)
    eprintln!("Warning: could not match key against DID document, using default fragment #key-0");
    Ok(format!("{did}#key-0"))
}

/// Find and load the signing config (repo-local first, then global).
fn load_config() -> Result<(PathBuf, SigningConfig)> {
    let config_path = if SigningConfig::repo_local_path().exists() {
        SigningConfig::repo_local_path()
    } else {
        SigningConfig::default_global_path()?
    };

    if !config_path.exists() {
        anyhow::bail!("No did-git-sign configuration found. Run `did-git-sign init` first.");
    }

    let cfg = SigningConfig::load(&config_path)?;
    Ok((config_path, cfg))
}

async fn cmd_verify() -> Result<()> {
    let (config_path, cfg) = load_config()?;
    println!("Config:     {}", config_path.display());
    println!("DID:        {}", cfg.did_key_id);

    // Check keyring
    print!("Keyring:    ");
    let creds = config::load_vta_credentials(&cfg.did_key_id)
        .context("VTA credentials not found in keyring")?;
    println!("OK (VTA: {})", creds.vta_url);

    // Authenticate with VTA
    print!("VTA auth:   ");
    let (client, creds) = vta::authenticate(&cfg).await?;
    println!("OK");

    // Fetch signing key
    print!("Fetch key:  ");
    let seed = vta::get_signing_key(&client, &creds.key_id).await?;
    println!("OK");

    // Test sign
    print!("Test sign:  ");
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();
    let test_data = b"did-git-sign verification test";
    sign::test_sign(&signing_key, &verifying_key, test_data)?;
    println!("OK");

    println!();
    println!("All checks passed. Signing is operational.");
    Ok(())
}

async fn cmd_health() -> Result<()> {
    let (config_path, cfg) = load_config()?;

    println!("did-git-sign health check");
    println!("=========================");
    println!();

    // Config
    println!("Config:          {}", config_path.display());
    println!("DID:             {}", cfg.did_key_id);
    if let Some(name) = &cfg.user_name {
        println!("User:            {name}");
    }
    println!();

    // Keyring
    let creds = config::load_vta_credentials(&cfg.did_key_id)
        .context("VTA credentials not found in keyring — run `did-git-sign init` first")?;
    println!("VTA URL:         {}", creds.vta_url);
    println!("VTA DID:         {}", creds.vta_did);
    println!("Credential DID:  {}", creds.credential_did);
    println!("Signing Key ID:  {}", creds.key_id);

    // Token cache
    match config::load_cached_token(&cfg.did_key_id) {
        Some(_) => println!("Token cache:     valid"),
        None => println!("Token cache:     empty or expired"),
    }
    println!();

    // VTA connectivity
    print!("VTA health:      ");
    let vta_client = vta_sdk::client::VtaClient::new(&creds.vta_url);
    match vta_client.health().await {
        Ok(health) => {
            println!("OK (v{})", health.version.as_deref().unwrap_or("unknown"));
            if let Some(mediator_did) = &health.mediator_did {
                println!("  Mediator DID:  {mediator_did}");
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {e}");
        }
    }

    // Authentication
    print!("VTA auth:        ");
    match vta::authenticate(&cfg).await {
        Ok((client, creds)) => {
            println!("OK");

            // Fetch signing key and show public key
            print!("Signing key:     ");
            match vta::get_signing_key(&client, &creds.key_id).await {
                Ok(seed) => {
                    let signing_key = SigningKey::from_bytes(seed.as_bytes());
                    let verifying_key = signing_key.verifying_key();
                    println!("OK");
                    println!();
                    println!("SSH Public Key (for signature verification):");
                    println!(
                        "  {}",
                        init::ssh_public_key_string(verifying_key.as_bytes())
                    );
                    println!();
                    println!("Allowed Signers Entry:");
                    println!(
                        "  {}",
                        init::allowed_signers_entry(&cfg, verifying_key.as_bytes())
                    );
                }
                Err(e) => {
                    println!("FAILED");
                    println!("  Error: {e}");
                }
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {e}");
        }
    }

    Ok(())
}

/// Delegate a verification operation to the system ssh-keygen binary.
///
/// did-git-sign only adds value during signing (VTA authentication to retrieve the key).
/// Verification is stateless and only requires the public key from the allowed_signers file,
/// which ssh-keygen handles natively. Rebuilding that logic here would duplicate it for no gain.
///
/// Git calls: `did-git-sign -Y verify -f <allowed_signers> -I <principal> -n git -s <sig_file>`
/// We forward this verbatim to: `ssh-keygen -Y verify ...`
fn delegate_to_ssh_keygen(op: &str, cli: &Cli) -> Result<i32> {
    // Allow the ssh-keygen binary path to be overridden via environment variable.
    // This is useful when did-git-sign is invoked by git in a stripped-down
    // environment (GUI clients, minimal CI containers) where ssh-keygen may not
    // be on the inherited $PATH.
    let ssh_keygen =
        std::env::var("DID_GIT_SIGN_SSH_KEYGEN").unwrap_or_else(|_| "ssh-keygen".to_string());

    let mut cmd = std::process::Command::new(&ssh_keygen);
    cmd.arg("-Y").arg(op);

    if let Some(f) = &cli.key_file {
        cmd.arg("-f").arg(f);
    }
    if let Some(i) = &cli.identity {
        cmd.arg("-I").arg(i);
    }
    if let Some(n) = &cli.namespace {
        cmd.arg("-n").arg(n);
    }
    if let Some(s) = &cli.sig_file {
        cmd.arg("-s").arg(s);
    }
    for opt in &cli.sig_option {
        cmd.arg("-O").arg(opt);
    }

    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context(format!(
            "failed to invoke ssh-keygen at {:?} — is ssh-keygen installed? \
             Set DID_GIT_SIGN_SSH_KEYGEN to override the path.",
            ssh_keygen
        ))?;

    // status.code() returns None when ssh-keygen was terminated by a signal rather
    // than exiting normally. We collapse that to exit code 1 (generic failure).
    // Re-raising the signal would be more faithful but requires platform-specific
    // libc calls and provides no practical benefit here — git treats both cases
    // identically (verification failed). The unwrap_or(1) is intentional.
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sets an env var on construction, removes it on drop (panic-safe).
    /// Requires `#[serial_test::serial]` — `set_var`/`remove_var` are `unsafe`
    /// in edition 2024 and safe only when no other thread reads the var
    /// concurrently. **Any future test reading `DID_GIT_SIGN_SSH_KEYGEN` or
    /// `DID_GIT_SIGN_TEST_MOCK_OUT` without `#[serial]` will race.**
    struct EnvVarGuard(&'static str);

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: see struct-level doc comment above.
            unsafe { std::env::remove_var(self.0) };
        }
    }

    fn set_test_env(key: &'static str, value: &str) -> EnvVarGuard {
        // SAFETY: see EnvVarGuard struct-level doc comment.
        unsafe { std::env::set_var(key, value) };
        EnvVarGuard(key)
    }

    /// Verifies that delegate_to_ssh_keygen forwards every flag in the Cli struct
    /// to the underlying ssh-keygen binary in the correct order, and that the
    /// DID_GIT_SIGN_SSH_KEYGEN env var is honoured for path override.
    ///
    /// The real ssh-keygen is replaced by a small shell script that writes each
    /// received argument on its own line to a temp file.  The test then asserts
    /// that every expected flag and value appears in that file.
    #[test]
    #[serial_test::serial]
    fn delegate_forwards_all_flags_to_ssh_keygen() {
        let mock_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock_ssh_keygen.sh");

        // Ensure the mock script is executable regardless of git checkout settings.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&mock_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&mock_path, perms).unwrap();
        }

        let out_file = tempfile::NamedTempFile::new().unwrap();
        let _ssh_guard = set_test_env("DID_GIT_SIGN_SSH_KEYGEN", mock_path.to_str().unwrap());
        let _out_guard = set_test_env(
            "DID_GIT_SIGN_TEST_MOCK_OUT",
            out_file.path().to_str().unwrap(),
        );

        // Build a Cli that mirrors what git passes for -Y verify:
        //   did-git-sign -Y verify -f allowed_signers -I <principal> -n git -s <sig> -O hashalg=sha512
        let cli = Cli::try_parse_from([
            "did-git-sign",
            "-Y",
            "verify",
            "-f",
            "allowed_signers",
            "-I",
            "did:webvh:test#key-0",
            "-n",
            "git",
            "-s",
            "buffer.diff.sig",
            "-O",
            "hashalg=sha512",
        ])
        .expect("clap should parse these flags without error");

        let code = delegate_to_ssh_keygen("verify", &cli).unwrap();
        assert_eq!(code, 0, "mock ssh-keygen must exit 0");

        // Each arg is written on its own line by the mock script.
        let content = std::fs::read_to_string(out_file.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert!(lines.contains(&"-Y"), "missing -Y flag");
        assert!(lines.contains(&"verify"), "missing operation");
        assert!(lines.contains(&"-f"), "missing -f flag");
        assert!(lines.contains(&"allowed_signers"), "missing key_file value");
        assert!(lines.contains(&"-I"), "missing -I flag");
        assert!(lines.contains(&"did:webvh:test#key-0"), "missing identity");
        assert!(lines.contains(&"-n"), "missing -n flag");
        assert!(lines.contains(&"git"), "missing namespace");
        assert!(lines.contains(&"-s"), "missing -s flag");
        assert!(lines.contains(&"buffer.diff.sig"), "missing sig_file");
        assert!(lines.contains(&"-O"), "missing -O flag");
        assert!(lines.contains(&"hashalg=sha512"), "missing sig_option");
    }
}
