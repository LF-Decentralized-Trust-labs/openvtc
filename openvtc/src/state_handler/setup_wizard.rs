#[cfg(feature = "openpgp-card")]
use crate::state_handler::setup_token_actions;
use crate::{
    Interrupted,
    state_handler::{
        SetupWizardExit, StateHandler,
        actions::Action,
        setup_did_actions, setup_did_git_sign_actions,
        setup_sequence::{Completion, MessageType, SetupPage, config::ConfigExtension},
        setup_vta_actions,
        state::{ActivePage, State},
    },
};
use affinidi_tdk::TDK;
use anyhow::Result;
use openvtc_core::config::Config;
use secrecy::SecretString;
use tokio::sync::{broadcast, mpsc::UnboundedReceiver};

impl StateHandler {
    pub(crate) async fn setup_wizard(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
    ) -> Result<SetupWizardExit> {
        state.active_page = ActivePage::Setup;

        // Holder for the created config
        let mut config: Option<Config> = None;
        // The single admin VTA session: opened once at provisioning (after the
        // ephemeral→admin DID swap) and reused by every subsequent VTA step, so
        // the admin DID holds ONE mediator connection for the whole flow rather
        // than a fresh WebSocket per call (which churns the mediator's
        // one-socket-per-DID policy and drops in-flight responses). Shut down
        // once when the wizard exits (below).
        let mut admin_client: Option<vta_sdk::client::VtaClient> = None;
        // Wrapped so the admin session is torn down on EVERY exit — including a
        // `?` error out of a handler below — and never leaks (the LeakGuard).
        let exit: Result<SetupWizardExit> = async {
            Ok(loop {
            let _ = self.state_tx.send(state.clone());
            tokio::select! {
            Some(action) = action_rx.recv() => match action {
                Action::Exit => {
                     break SetupWizardExit::Interrupted(Interrupted::UserInt);
                },
                Action::UXError(interrupted) => {
                    break  SetupWizardExit::Interrupted(interrupted);
                },
                Action::ImportConfig(filename, import_unlock_passphrase, new_unlock_passphrase) => {
                    // Import a configuration backup
                    let import_unlock_passphrase = SecretString::new(import_unlock_passphrase.into());
                    let new_unlock_passphrase = SecretString::new(new_unlock_passphrase.into());
                    state.setup.active_page = SetupPage::ConfigImport;
                    match Config::import(
                        state, &self.state_tx,
                        &import_unlock_passphrase,
                        &new_unlock_passphrase,
                        &filename,
                        &self.profile,
                    ) {
                        Ok(()) => {
                            state.setup.config_import.completed = Completion::CompletedOK;
                            state.setup.config_import.messages.push(MessageType::Info("Configuration import completed successfully.".to_string()));
                        }
                        Err(e) => {
                            state.setup.config_import.messages.push(MessageType::Error(format!("Importing Config failed: {e}")));
                            state.setup.config_import.completed = Completion::CompletedFail;
                        }
                    }
                },
                Action::ActivateMainMenu => {
                    // Switch to Main Menu
                    state.active_page = ActivePage::Main;
                    state.main_page.menu_panel.selected = true;
                    state.main_page.content_panel.selected = false;

                    if let Some(cfg) = config {
                        break SetupWizardExit::Config(Box::new(cfg));
                    } else {
                        state.setup.final_page.messages.push(MessageType::Error("Setup Wizard completed but no configuration was created.".to_string()));
                    }
                },
                Action::SetProtection(protection, next_page) => {
                    state.setup.protection = protection;
                    state.setup.active_page = next_page;
                },
                Action::SetDIDKeys(keys) => {
                    state.setup.did_keys = Some(*keys);
                    state.setup.active_page = SetupPage::DIDKeysShow;
                },
                Action::VtaSubmitDid(vta_did) => {
                    setup_vta_actions::handle_vta_submit_did(state, &self.state_tx, vta_did).await?;
                },
                Action::VtaStartProvision(context_id) => {
                    // Close any prior admin session before re-provisioning.
                    if let Some(c) = admin_client.take() {
                        c.shutdown().await;
                    }
                    admin_client = setup_vta_actions::handle_vta_start_provision(state, &self.state_tx, context_id).await?;
                },
                Action::VtaCreateKeys
                    if setup_vta_actions::handle_vta_create_keys(state, &self.state_tx, admin_client.as_ref()).await? =>
                {
                    continue;
                },
                Action::ExportDIDKeys(export_inputs) => {
                    setup_did_actions::handle_export_did_keys(state, &self.state_tx, export_inputs).await;
                },
                Action::DidGitSignInstall => {
                    setup_did_git_sign_actions::handle_did_git_sign_install(state, &self.state_tx).await?;
                },
                #[cfg(feature = "openpgp-card")]
                Action::GetTokens => {
                    setup_token_actions::handle_get_tokens(state);
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetAdminPin(token, admin_pin) => {
                    setup_token_actions::handle_set_admin_pin(state, token, admin_pin);
                },
                #[cfg(feature = "openpgp-card")]
                Action::FactoryReset(token) => {
                    setup_token_actions::handle_factory_reset(state, token).await;
                },
                #[cfg(feature = "openpgp-card")]
                Action::TokenWriteKeys(token) => {
                    setup_token_actions::handle_token_write_keys(state, &self.state_tx, token).await;
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetTouchPolicy(token) => {
                    setup_token_actions::handle_set_touch_policy(state, &self.state_tx, token);
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetTokenName(token, name) => {
                    setup_token_actions::handle_set_token_name(state, &self.state_tx, token, &name);
                },
                Action::WebvhServerCreateDid(server_id, path_mode) => {
                    // Cannot move owned bound vars into a match guard, so the
                    // collapsible_match form clippy suggests doesn't compile.
                    #[allow(clippy::collapsible_match)]
                    if setup_did_actions::handle_webvh_server_create_did(state, &self.state_tx, tdk, admin_client.as_ref(), server_id, path_mode).await? {
                        continue;
                    }
                },
                Action::SetCustomMediator(mediator_did) => {
                    state.setup.custom_mediator = Some(mediator_did.clone());
                    if state.setup.vta.use_webvh_server {
                        if setup_did_actions::handle_custom_mediator_webvh(state, &self.state_tx, tdk, admin_client.as_ref()).await? {
                            continue;
                        }
                    } else {
                        state.setup.active_page = SetupPage::UserName;
                    }
                },
                Action::SetUsername(username) => {
                    state.setup.username = username;
                    if state.setup.vta.use_webvh_server {
                        state.setup.active_page = SetupPage::FinalPage;
                    } else {
                        state.setup.active_page = SetupPage::WebVHAddress;
                    }
                },
                Action::CreateWebVHDID(webvh_address) => {
                    #[allow(clippy::collapsible_match)]
                    if setup_did_actions::handle_create_webvh_did(state, &self.profile, webvh_address).await? {
                        continue;
                    }
                },
                Action::ResetWebVHDID => {
                    state.setup.webvh_address.messages.clear();
                    state.setup.webvh_address.completed = Completion::NotFinished;
                },
                Action::ResolveWebVHDID(did) => {
                    setup_did_actions::handle_resolve_webvh_did(state, tdk, did).await;
                },
                Action::SetupCompleted(_setup_flow) => {
                    state.setup.active_page = SetupPage::FinalPage;
                    // The armored private-key block is no longer needed once we
                    // leave the export page; drop it so it stops being cloned
                    // out on every state broadcast.
                    state.setup.did_keys_export.exported = None;
                    state.setup.final_page.messages.push(MessageType::Info("Creating your account configuration...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Securing sensitive data for storage...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Your device may prompt for authentication to access OS secure storage.".to_string()));
                    let _ = self.state_tx.send(state.clone());
                    // R-A-5: setup now bootstraps a State-A account (VTA admin
                    // credential + top-level context, no persona/community). A
                    // persona is minted later by the State-B join flow.
                    match Config::create_account(&state.setup, &self.profile).await {
                        Ok(cfg) => {
                            state.setup.final_page.completed = Completion::CompletedOK;
                            state.setup.final_page.messages.push(MessageType::Info("Account setup completed successfully.".to_string()));
                            config = Some(cfg);
                        },
                        Err(e) => {
                            state.setup.final_page.completed = Completion::CompletedFail;
                            state.setup.final_page.messages.push(MessageType::Error(format!("Couldn't create OpenVTC account. Reason: {e}")));
                        }
                    }
                },
                _ => {}
            },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break SetupWizardExit::Interrupted(interrupted);
                }
            }
            })
        }
        .await;

        // Tear down the single admin VTA session now that setup is over (no-op
        // for the REST transport). This is the one place the wizard's session is
        // closed — every VTA step above reused it without opening its own.
        if let Some(c) = admin_client {
            c.shutdown().await;
        }

        exit
    }
}
