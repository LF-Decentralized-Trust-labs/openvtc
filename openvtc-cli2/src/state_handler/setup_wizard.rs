use crate::{
    Interrupted,
    state_handler::{
        SetupWizardExit, StateHandler,
        actions::Action,
        setup_did_actions,
        setup_sequence::{Completion, MessageType, SetupPage, config::ConfigExtension},
        setup_token_actions, setup_vta_actions,
        state::{ActivePage, State},
    },
};
use affinidi_tdk::TDK;
use anyhow::Result;
use openvtc::config::Config;
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
        let exit = loop {
            self.state_tx.send(state.clone())?;
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
                    let import_unlock_passphrase = SecretString::new(import_unlock_passphrase);
                    let new_unlock_passphrase = SecretString::new(new_unlock_passphrase);
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
                Action::VtaSubmitCredential(credential_input) => {
                    setup_vta_actions::handle_vta_submit_credential(state, &self.state_tx, credential_input).await?;
                },
                Action::VtaAuthenticate => {
                    if setup_vta_actions::handle_vta_authenticate(state, &self.state_tx).await? {
                        continue;
                    }
                },
                Action::VtaCreateKeys => {
                    if setup_vta_actions::handle_vta_create_keys(state, &self.state_tx).await? {
                        continue;
                    }
                },
                Action::ExportDIDKeys(export_inputs) => {
                    setup_did_actions::handle_export_did_keys(state, &self.state_tx, export_inputs).await;
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
                Action::WebvhServerCreateDid(server_id, custom_path) => {
                    if setup_did_actions::handle_webvh_server_create_did(state, &self.state_tx, tdk, server_id, custom_path).await? {
                        continue;
                    }
                },
                Action::SetCustomMediator(mediator_did) => {
                    state.setup.custom_mediator = Some(mediator_did.clone());
                    if state.setup.vta.use_webvh_server {
                        if setup_did_actions::handle_custom_mediator_webvh(state, &self.state_tx, tdk).await? {
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
                    if setup_did_actions::handle_create_webvh_did(state, webvh_address).await? {
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
                Action::SetupCompleted(setup_flow) => {
                    state.setup.active_page = SetupPage::FinalPage;
                    state.setup.final_page.messages.push(MessageType::Info("Generating your profile configuration...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Securing sensitive data for storage...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Your device may prompt for authentication to access OS secure storage.".to_string()));
                    self.state_tx.send(state.clone())?;
                    match Config::create(&state.setup, &setup_flow, tdk, &self.profile).await {
                        Ok(cfg) => {
                            state.setup.final_page.completed = Completion::CompletedOK;
                            state.setup.final_page.messages.push(MessageType::Info("Profile setup completed successfully.".to_string()));
                            config = Some(cfg);
                        },
                        Err(e) => {
                            state.setup.final_page.completed = Completion::CompletedFail;
                            state.setup.final_page.messages.push(MessageType::Error(format!("Couldn't create OpenVTC configuration. Reason: {e}")));
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
        };

        Ok(exit)
    }
}
