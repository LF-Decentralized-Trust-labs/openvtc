use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dialoguer::{Select, theme::ColorfulTheme};
use did_git_sign::{config, init, sign, vta};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

use config::SigningConfig;

/// Run `provision_client::run_connection_test` against the VTA with the
/// given setup did:key, drain its `VtaEvent` stream to stdout, and return
/// the issued admin credential. Errors out if provisioning fails or
/// completes without an admin VC.
async fn run_provision(
    vta_did: &str,
    context: &str,
    setup_key: &vta_sdk::provision_client::EphemeralSetupKey,
) -> Result<vta_sdk::provision_client::AdminCredentialReply> {
    use vta_sdk::provision_client::{
        AdminCredentialReply, DiagStatus, ProvisionAsk, VtaEvent, VtaIntent, VtaReply,
        run_connection_test,
    };

    println!("Bootstrapping with the VTA…");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
    // AdminRotated rolls the ephemeral setup did:key over to a fresh
    // long-term admin DID server-side, so the credential we persist
    // doesn't carry the setup key's `--admin-expires 1h` lifetime.
    let ask = ProvisionAsk::vta_admin_rotated(context.to_string()).with_label("did-git-sign");
    let setup_did = setup_key.did.clone();
    let setup_priv = setup_key.private_key_multibase().to_string();
    let runner_vta_did = vta_did.to_string();
    tokio::spawn(async move {
        run_connection_test(
            VtaIntent::AdminRotated,
            runner_vta_did,
            setup_did,
            setup_priv,
            ask,
            None,
            tx,
        )
        .await;
    });

    let mut admin_reply: Option<AdminCredentialReply> = None;
    let mut failure: Option<String> = None;
    while let Some(ev) = rx.recv().await {
        match ev {
            VtaEvent::CheckStart(check) => {
                println!("  · {}…", check.label());
            }
            VtaEvent::CheckDone(check, status) => match status {
                DiagStatus::Ok(detail) => println!("  ✓ {} — {detail}", check.label()),
                DiagStatus::Skipped(detail) => {
                    println!("  · {} (skipped: {detail})", check.label())
                }
                DiagStatus::Failed(detail) => println!("  ✗ {} — {detail}", check.label()),
                DiagStatus::Pending | DiagStatus::Running => {}
            },
            VtaEvent::Resolved(_)
            | VtaEvent::AttemptCompleted { .. }
            | VtaEvent::PreflightDone { .. } => {}
            VtaEvent::Connected { reply, .. } => {
                if let VtaReply::AdminOnly(adm) = reply {
                    admin_reply = Some(adm);
                }
            }
            VtaEvent::Failed(reason) => {
                failure = Some(reason);
            }
        }
    }

    if let Some(reason) = failure {
        bail!("provisioning failed: {reason}");
    }
    admin_reply.context("provisioning ended without an admin credential")
}

/// Register the platform-specific keyring-core credential store as the
/// process default. Must run before any `keyring_core::Entry::new` call.
fn init_default_keyring_store() -> Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| anyhow::anyhow!("init macOS keychain store: {e}"))?;
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init linux keyutils store: {e}"))?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init Windows credential manager store: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

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

        /// VTA DID. The service URL is discovered from the DID document
        /// (overridable with `--vta-url`). did-git-sign mints a temporary
        /// admin did:key for this setup session and prints a `pnm contexts
        /// create` command for you to run before bootstrapping.
        #[arg(long)]
        vta_did: String,

        /// Context id to provision into. Pass the same value to
        /// `pnm contexts create --id <ctx>`.
        #[arg(long, default_value = "did-git-sign")]
        context: String,

        /// Git user.name to set
        #[arg(long)]
        name: Option<String>,

        /// VTA URL (overrides DID document discovery)
        #[arg(long)]
        vta_url: Option<String>,

        /// VTA key ID for the signing key (skip interactive selection)
        #[arg(long)]
        key_id: Option<String>,

        /// DID#key-id to use as signing identity (skip interactive selection)
        #[arg(long)]
        did_key_id: Option<String>,

        /// Skip the "press Enter once authorised" prompt — assume the PNM
        /// ACL grant has already been registered. Useful for scripted
        /// setups.
        #[arg(long)]
        yes: bool,
    },

    /// Verify the signing setup by performing a test sign operation
    Verify,

    /// Check configuration, VTA connectivity, and show signing public key
    Health,

    /// Remove this host's did-git-sign install: deletes the JSON config,
    /// drops the keyring entries, strips the matching allowed_signers
    /// line, and unsets the relevant git config keys. Idempotent — safe
    /// to run on a partial / already-clean install.
    Uninstall {
        /// Tear down the global install (`~/.config/did-git-sign/`).
        /// Mutually exclusive with `--local`; when neither is given, the
        /// command auto-detects whichever install exists at the current
        /// working directory and falls back to global.
        #[arg(long)]
        global: bool,

        /// Tear down the repo-local install (`.did-git-sign.json`).
        #[arg(long, conflicts_with = "global")]
        local: bool,

        /// Override the principal to remove. By default the value is read
        /// from the SigningConfig file. Only set this when the file is
        /// missing but you still need to clear keyring entries.
        #[arg(long)]
        did_key_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Register the platform's keyring-core credential store before any
    // Entry::new call. Same backend choice as openvtc so credential
    // namespaces line up across both binaries.
    init_default_keyring_store()?;

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
                // NOTE: process::exit skips tokio runtime shutdown AND any
                // `Drop` impls on stack-resident values. Safe here because:
                //   1. no async work happens in this branch after delegation;
                //   2. inherited stdio (stdout/stderr) doesn't buffer
                //      in-process — bytes have already crossed the syscall
                //      boundary by the time we reach this line, so there's
                //      nothing to flush.
                // If a future edit introduces `println!`/`eprintln!` between
                // the delegation and this exit, point (2) no longer holds —
                // switch to a clean `return Ok(())` from main and propagate
                // the exit code via the `Result` instead.
                std::process::exit(code);
            }
        }
    }

    match cli.command {
        Some(Commands::Init {
            global,
            vta_did,
            context,
            name,
            vta_url,
            key_id,
            did_key_id,
            yes,
        }) => {
            cmd_init(
                global, vta_did, context, name, vta_url, key_id, did_key_id, yes,
            )
            .await
        }
        Some(Commands::Verify) => cmd_verify().await,
        Some(Commands::Health) => cmd_health().await,
        Some(Commands::Uninstall {
            global,
            local,
            did_key_id,
        }) => cmd_uninstall(global, local, did_key_id),
        None => {
            // `sign_file` is only legitimate when `-Y sign` is set (git signing
            // invocation), which is handled in the early-return block above. If
            // we reach this arm with `sign_file` populated, the user typed an
            // unrecognised subcommand — without this guard, typos like
            // `did-git-sign verfy` silently fall through to help.
            //
            // (No nested `cli.operation.is_none()` check: the early-return
            // block consumes any `-Y` operation before we get here, so it's
            // always `None` in this arm.)
            if let Some(f) = &cli.sign_file {
                anyhow::bail!(
                    "unrecognised subcommand {:?}\n\nUsage: did-git-sign [COMMAND]\n\nRun 'did-git-sign --help' for available commands.",
                    f.display()
                );
            }
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_init(
    global: bool,
    vta_did: String,
    context: String,
    user_name: Option<String>,
    vta_url_override: Option<String>,
    key_id_override: Option<String>,
    did_key_id_override: Option<String>,
    yes: bool,
) -> Result<()> {
    // 1. Resolve the VTA service URL (or take the override).
    let vta_url = if let Some(url) = vta_url_override {
        url
    } else {
        println!("Resolving VTA service endpoint from {vta_did}…");
        vta_sdk::session::resolve_vta_url(&vta_did)
            .await
            .map_err(|e| anyhow::anyhow!("could not resolve VTA URL from {vta_did}: {e}"))?
    };
    println!("VTA URL: {vta_url}");

    // 2. Mint a fresh ephemeral did:key as the admin identity for this
    //    setup session. Held in memory only — if did-git-sign is rerun the
    //    operator must re-grant the ACL for the new DID.
    let setup_key = vta_sdk::provision_client::EphemeralSetupKey::generate()
        .map_err(|e| anyhow::anyhow!("failed to generate setup did:key: {e}"))?;

    // 3. Show the operator the matching `pnm contexts create` command and
    //    wait for them to confirm it has run (skippable with --yes).
    println!();
    println!("did-git-sign has minted a temporary admin DID for this setup session:");
    println!("  {}", setup_key.did);
    println!();
    println!("Authorise it on the VTA via your Personal Network Manager (PNM):");
    println!();
    println!("    pnm contexts create --id {context} --name \"did-git-sign\" \\");
    println!("        --admin-did {} --admin-expires 1h", setup_key.did);
    println!();
    if !yes {
        println!("The admin grant is short-lived (1h). Once the command above has run,");
        print!("press Enter to continue (or Ctrl+C to abort)... ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read confirmation from stdin")?;
    }

    // 4. Bootstrap with the VTA. provision_client handles the resolve →
    //    enumerate → authenticate → issue-admin-VC pipeline; we drain its
    //    event stream into stdout so the operator can see progress.
    let admin = run_provision(&vta_did, &context, &setup_key).await?;

    // 5. Authenticate as the issued admin DID and proceed with the existing
    //    interactive context / DID / key picker.
    println!();
    println!("Authenticating as {}…", admin.admin_did);
    let client = vta_sdk::client::VtaClient::new(&vta_url);
    let token = vta_sdk::session::challenge_response(
        &vta_url,
        &admin.admin_did,
        &admin.admin_private_key_mb,
        &vta_did,
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

    // Fetch the persona signing key so we know its public bytes for the
    // allowed_signers entry. Uses the freshly-issued admin token.
    let seed = vta::get_signing_key(&client, &key_id).await?;
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();

    // Cache the token we already have so the very next sign operation
    // doesn't have to re-auth.
    let _ = config::cache_token(&did_key_id, &token.access_token, token.access_expires_at);

    let result = init::install(init::InstallArgs {
        global,
        did_key_id: did_key_id.clone(),
        vta_key_id: key_id,
        credential_did: admin.admin_did.clone(),
        credential_private_key_mb: admin.admin_private_key_mb.clone(),
        vta_did: vta_did.clone(),
        vta_url,
        // Standalone CLI install path uses REST today; the openvtc setup
        // flow populates this via its own InstallArgs construction.
        // A follow-up could plumb DIDComm into this path too.
        mediator_did: None,
        user_name,
        verifying_key: verifying_key.as_bytes(),
    })?;

    println!("Config saved to: {}", result.config_path.display());
    println!("VTA credentials stored in OS keyring");
    println!("Git configured for DID signing");
    println!("Allowed signers file updated");

    if let Some(prev) = result.overridden_global_signing_key {
        println!();
        println!("Note: your global user.signingKey ({prev}) has been overridden locally");
        println!("      for this repository. did-git-sign uses its JSON config file as the");
        println!("      signing key path. Your global signing configuration is unchanged.");
    }

    println!();
    println!("Setup complete! Git commits will now be signed with:");
    println!("  DID: {did_key_id}");
    println!("  Key: {}", result.ssh_public_key);
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

fn cmd_uninstall(
    global_flag: bool,
    local_flag: bool,
    did_key_id_override: Option<String>,
) -> Result<()> {
    // Decide which install scope to tear down. `--global` / `--local`
    // pin the choice; otherwise auto-detect: prefer the repo-local
    // install when one is present at the CWD, falling back to global.
    let global = if global_flag {
        true
    } else {
        !(local_flag || SigningConfig::repo_local_path().exists())
    };

    // Discover did_key_id: explicit override, or read from the
    // SigningConfig file at this scope. The keyring entries are keyed
    // by it, so we need it to clear them.
    let config_path = if global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };
    let did_key_id = match did_key_id_override {
        Some(id) => id,
        None => match SigningConfig::load(&config_path) {
            Ok(cfg) => cfg.did_key_id,
            Err(e) => {
                bail!(
                    "could not read {} to discover the principal — pass --did-key-id explicitly: {e}",
                    config_path.display()
                );
            }
        },
    };

    let summary = init::uninstall(global, &did_key_id)?;

    if let Some(path) = &summary.removed_config_file {
        println!("Removed config: {}", path.display());
    } else {
        println!("Config file already absent");
    }
    if !summary.removed_keyring_entries.is_empty() {
        for key in &summary.removed_keyring_entries {
            println!("Removed keyring entry: {key}");
        }
    } else {
        println!("Keyring entries already absent");
    }
    if summary.allowed_signers_entry_removed {
        println!("Removed allowed_signers entry for {did_key_id}");
    }
    if !summary.git_config_keys_unset.is_empty() {
        let scope = if global { "--global" } else { "--local" };
        for key in &summary.git_config_keys_unset {
            println!("Unset git config {scope} {key}");
        }
    }
    for w in &summary.warnings {
        eprintln!("warning: {w}");
    }
    println!();
    println!("did-git-sign install removed.");
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
