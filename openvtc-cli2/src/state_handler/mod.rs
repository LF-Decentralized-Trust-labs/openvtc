#[cfg(feature = "openpgp-card")]
use crate::state_handler::setup_sequence::openpgp_card::{
    set_cardholder_name, set_signing_touch_policy, write_keys_to_card,
};
use crate::{
    Interrupted, Terminator,
    state_handler::{
        actions::Action,
        main_page::MainPanel,
        setup_sequence::{
            Completion, ConfigProtection, MessageType, SetupPage, config::ConfigExtension,
            did_keys::export_persona_did_keys,
        },
        state::{ActivePage, State},
    },
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use anyhow::Result;
#[cfg(feature = "openpgp-card")]
use openvtc::openpgp_card::{factory_reset, get_cards};
use openvtc::{
    LF_PUBLIC_MEDIATOR_DID,
    config::{Config, did::create_initial_webvh_did},
};
use pgp::composed::ArmorOptions;
use secrecy::SecretString;
use std::str::FromStr;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

pub mod actions;
pub mod main_page;
pub mod messaging;
pub mod setup_sequence;
pub mod state;

pub enum StartingMode {
    NotSet,
    MainPage(Box<Config>, TDK),
    SetupWizard,
}

pub struct StateHandler {
    state_tx: UnboundedSender<State>,
    profile: String,
    starting_mode: StartingMode,
}

enum SetupWizardExit {
    Interrupted(Interrupted),
    Config(Box<Config>),
}

impl StateHandler {
    pub fn new(profile: &str, starting_mode: StartingMode) -> (Self, UnboundedReceiver<State>) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<State>();

        (
            StateHandler {
                state_tx,
                profile: profile.to_string(),
                starting_mode,
            },
            state_rx,
        )
    }

    pub async fn main_loop(
        self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let mut state = State::default();

        let (tdk, config) = match self.starting_mode {
            StartingMode::MainPage(config, tdk) => {
                state.active_page = ActivePage::Main;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = (&config).into();

                (tdk.to_owned(), config)
            }
            StartingMode::SetupWizard => {
                // Instantiate TDK
                let tdk = TDK::new(
                    TDKConfig::builder().with_load_environment(false).build()?,
                    None,
                )
                .await?;

                match self
                    .setup_wizard(&mut action_rx, &mut interrupt_rx, &mut state, &tdk)
                    .await
                {
                    Ok(SetupWizardExit::Config(mut config)) => {
                        crate::apply_env_overrides(&mut config);
                        (tdk, config)
                    }
                    Ok(SetupWizardExit::Interrupted(interrupted)) => {
                        let _ = terminator.terminate(interrupted.clone());
                        return Ok(interrupted);
                    }
                    Err(e) => {
                        let interrupted = Interrupted::SystemError(format!(
                            "Setup Wizard failed with error: {}",
                            e
                        ));
                        let _ = terminator.terminate(interrupted.clone());
                        return Ok(interrupted);
                    }
                }
            }
            StartingMode::NotSet => {
                let _ = terminator.terminate(Interrupted::SystemError(
                    "Starting Mode is Not Set!".to_string(),
                ));
                return Ok(Interrupted::SystemError(
                    "Starting Mode is Not Set!".to_string(),
                ));
            }
        };

        // Initialize DIDComm messaging
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        let msg_task_handle = if let Some((atm, profile)) =
            messaging::init_didcomm_connection(&tdk, &config).await
        {
            state.connection.status = state::MediatorStatus::Connecting;
            self.state_tx.send(state.clone())?;

            // Validate the mediator connection with a trust-ping (10s timeout)
            let persona_did = config.public.persona_did.to_string();
            let mediator_did = config.public.mediator_did.clone();
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                messaging::validate_mediator_connection(
                    &atm,
                    &profile,
                    &mediator_did,
                    &persona_did,
                ),
            )
            .await
            {
                Ok(Ok(latency_ms)) => {
                    state.connection.status =
                        state::MediatorStatus::Connected { latency_ms };
                    state.connection.last_ping_latency_ms = Some(latency_ms);
                }
                Ok(Err(e)) => {
                    state.connection.status =
                        state::MediatorStatus::Failed(format!("{e}"));
                }
                Err(_) => {
                    state.connection.status =
                        state::MediatorStatus::Failed("trust-ping timed out".to_string());
                }
            }

            // Spawn the message loop
            let handle = tokio::spawn(messaging::run_didcomm_loop(
                atm,
                profile,
                persona_did,
                msg_tx,
                interrupt_rx.resubscribe(),
            ));
            state.connection.messaging_active = true;
            Some(handle)
        } else {
            None
        };

        // Send the initial state once
        self.state_tx.send(state.clone())?;

        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    Action::Exit => {
                        let _ = terminator.terminate(Interrupted::UserInt);

                        break Interrupted::UserInt;
                    },
                    Action::UXError(interrupted) => {
                        // An error has occurred on the UX side
                        let _ = terminator.terminate(interrupted.clone());

                        break interrupted;
                    },
                    Action::MainMenuSelected(menu_item) => {
                        // User has changed main menu selection
                        state.main_page.menu_panel.selected_menu = menu_item;
                    },
                    Action::MainPanelSwitch(panel) => {
                        match panel {
                            MainPanel::ContentPanel => {
                                // When switching to ContentPanel, reset any content-specific state if needed
                                state.main_page.menu_panel.selected = false;
                                state.main_page.content_panel.selected = true;
                            },
                            MainPanel::MainMenu => {
                                // When switching to MainMenu, reset any content-specific state if needed
                                state.main_page.menu_panel.selected = true;
                                state.main_page.content_panel.selected = false;
                            }
                        }
                    },
                    _ => {}
                },
                Some(event) = msg_rx.recv() => {
                    match event {
                        messaging::MessagingEvent::TrustPingReceived { .. } => {}
                        messaging::MessagingEvent::TrustPongReceived { latency_ms, .. } => {
                            if let Some(ms) = latency_ms {
                                state.connection.last_ping_latency_ms = Some(ms);
                            }
                        }
                        messaging::MessagingEvent::ConnectionStatus(status) => {
                            match status {
                                messaging::ConnectionStatus::Connected => {
                                    state.connection.status = state::MediatorStatus::Connected {
                                        latency_ms: state.connection.last_ping_latency_ms.unwrap_or(0),
                                    };
                                }
                                messaging::ConnectionStatus::Disconnected => {
                                    state.connection.status = state::MediatorStatus::Unknown;
                                    state.connection.messaging_active = false;
                                }
                                messaging::ConnectionStatus::Error(e) => {
                                    state.connection.status = state::MediatorStatus::Failed(e);
                                }
                            }
                        }
                        messaging::MessagingEvent::InboundMessage { .. } => {}
                    }
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            self.state_tx.send(state.clone())?;
        };

        // Wait for messaging task to finish shutdown
        if let Some(handle) = msg_task_handle {
            let _ = handle.await;
        }

        Ok(result)
    }

    async fn setup_wizard(
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
                            // Somehow we don't have a config - this is a code logic error
                            state.setup.final_page.messages.push(MessageType::Error("Setup Wizard completed but no configuration was created.".to_string()));
                        }
                    },
                Action::SetProtection(protection, next_page) => {
                        // Set the Config Protection method in setup state
                        state.setup.protection = protection;
                        state.setup.active_page = next_page;
                    },

                Action::SetDIDKeys(keys) => {
                        // Set the DID Persona Keys in setup state
                        state.setup.did_keys = Some(*keys);
                        state.setup.active_page = SetupPage::DIDKeysShow;
                    },
                Action::VtaSubmitCredential(credential_input) => {
                        // Decode and validate the VTA credential bundle, then auto-authenticate
                        use crate::state_handler::setup_sequence::vta;
                        match vta::decode_credential(&credential_input) {
                            Ok(bundle) => {
                                // Resolve VTA URL from DID document's #vta service endpoint,
                                // falling back to bundle URL if resolution fails
                                let vta_url = match vta_sdk::session::resolve_vta_url(&bundle.vta_did).await {
                                    Ok(url) => url,
                                    Err(_) => bundle.vta_url.clone().unwrap_or_default(),
                                };
                                state.setup.vta.credential_bundle_raw = Some(credential_input);
                                state.setup.vta.credential_did = bundle.did.clone();
                                state.setup.vta.vta_url = vta_url.clone();
                                state.setup.vta.vta_did = bundle.vta_did.clone();
                                state.setup.vta.messages.clear();
                                state.setup.vta.completed = Completion::NotFinished;
                                state.setup.active_page = SetupPage::VtaAuthenticate;

                                // Pre-populate mediator DID from #didcomm service endpoint
                                if let Ok(Some(mediator_did)) = vta_sdk::session::resolve_mediator_did(&bundle.vta_did).await {
                                    state.setup.custom_mediator = Some(mediator_did);
                                }

                                state.setup.vta.messages.push(MessageType::Info(format!("VTA URL: {}", vta_url)));
                                state.setup.vta.messages.push(MessageType::Info("Authenticating with VTA...".to_string()));
                                self.state_tx.send(state.clone())?;

                                // Auto-trigger authentication inline
                                match vta::authenticate(
                                    &vta_url,
                                    &bundle.did,
                                    &bundle.private_key_multibase,
                                    &bundle.vta_did,
                                ).await {
                                    Ok(token_result) => {
                                        state.setup.vta.access_token = Some(token_result.access_token);
                                        state.setup.vta.authenticated = true;
                                        state.setup.vta.messages.push(MessageType::Info("VTA authentication successful.".to_string()));
                                        state.setup.vta.completed = Completion::CompletedOK;

                                        // Discover admin's allowed contexts from ACL
                                        {
                                            use vta_sdk::client::VtaClient;
                                            let mut acl_client = VtaClient::new(&vta_url);
                                            acl_client.set_token(state.setup.vta.access_token.clone().unwrap());
                                            match acl_client.get_acl(&state.setup.vta.credential_did).await {
                                                Ok(acl) => {
                                                    if acl.allowed_contexts.len() == 1 {
                                                        state.setup.vta.context_id = Some(acl.allowed_contexts[0].clone());
                                                        state.setup.vta.messages.push(MessageType::Info(
                                                            format!("Context: {}", acl.allowed_contexts[0]),
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    state.setup.vta.messages.push(MessageType::Info(
                                                        format!("Could not discover context: {e}"),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        state.setup.vta.messages.push(MessageType::Error(format!("Authentication failed: {e}")));
                                        state.setup.vta.completed = Completion::CompletedFail;
                                    }
                                }
                            }
                            Err(e) => {
                                state.setup.vta.messages = vec![MessageType::Error(format!("Invalid credential bundle: {e}"))];
                                state.setup.vta.completed = Completion::CompletedFail;
                            }
                        }
                    },
                Action::VtaAuthenticate => {
                        // Retry authentication with VTA using challenge-response
                        use crate::state_handler::setup_sequence::vta;
                        state.setup.vta.messages.clear();
                        state.setup.vta.completed = Completion::NotFinished;
                        state.setup.active_page = SetupPage::VtaAuthenticate;
                        state.setup.vta.messages.push(MessageType::Info("Authenticating with VTA...".to_string()));
                        self.state_tx.send(state.clone())?;

                        let credential_raw = state.setup.vta.credential_bundle_raw.clone().unwrap();
                        let bundle = vta::decode_credential(&credential_raw).unwrap();

                        // Resolve VTA URL from DID document, falling back to stored URL
                        let vta_url = match vta_sdk::session::resolve_vta_url(&bundle.vta_did).await {
                            Ok(url) => url,
                            Err(_) => state.setup.vta.vta_url.clone(),
                        };

                        match vta::authenticate(
                            &vta_url,
                            &bundle.did,
                            &bundle.private_key_multibase,
                            &bundle.vta_did,
                        ).await {
                            Ok(token_result) => {
                                state.setup.vta.access_token = Some(token_result.access_token);
                                state.setup.vta.authenticated = true;
                                state.setup.vta.messages.push(MessageType::Info("VTA authentication successful.".to_string()));
                                state.setup.vta.completed = Completion::CompletedOK;

                                // Discover admin's allowed contexts from ACL
                                {
                                    use vta_sdk::client::VtaClient;
                                    let mut acl_client = VtaClient::new(&vta_url);
                                    acl_client.set_token(state.setup.vta.access_token.clone().unwrap());
                                    match acl_client.get_acl(&state.setup.vta.credential_did).await {
                                        Ok(acl) => {
                                            if acl.allowed_contexts.len() == 1 {
                                                state.setup.vta.context_id = Some(acl.allowed_contexts[0].clone());
                                                state.setup.vta.messages.push(MessageType::Info(
                                                    format!("Context: {}", acl.allowed_contexts[0]),
                                                ));
                                            }
                                        }
                                        Err(e) => {
                                            state.setup.vta.messages.push(MessageType::Info(
                                                format!("Could not discover context: {e}"),
                                            ));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                state.setup.vta.messages.push(MessageType::Error(format!("Authentication failed: {e}")));
                                state.setup.vta.completed = Completion::CompletedFail;
                            }
                        }
                    },
                Action::VtaCreateKeys => {
                        // Create keys via VTA service
                        use crate::state_handler::setup_sequence::vta;
                        use vta_sdk::client::VtaClient;
                        state.setup.vta.messages.clear();
                        state.setup.vta.completed = Completion::NotFinished;
                        state.setup.active_page = SetupPage::VtaKeysFetch;
                        state.setup.vta.messages.push(MessageType::Info("Creating persona keys via VTA...".to_string()));
                        self.state_tx.send(state.clone())?;

                        let access_token = state.setup.vta.access_token.clone().unwrap();
                        let vta_url = state.setup.vta.vta_url.clone();
                        let mut client = VtaClient::new(&vta_url);
                        client.set_token(access_token);

                        // Create persona keys (signing, authentication, encryption)
                        let context_id = state.setup.vta.context_id.as_deref();
                        match vta::create_persona_keys(&client, context_id).await {
                            Ok(persona_keys) => {
                                state.setup.vta.messages.push(MessageType::Info("Persona keys created successfully.".to_string()));
                                self.state_tx.send(state.clone())?;

                                // Create WebVH update keys
                                state.setup.vta.messages.push(MessageType::Info("Creating WebVH update keys...".to_string()));
                                self.state_tx.send(state.clone())?;

                                match vta::create_update_keys(&client, context_id).await {
                                    Ok((update_secret, next_update_secret)) => {
                                        state.setup.vta.update_secret = Some(update_secret);
                                        state.setup.vta.next_update_secret = Some(next_update_secret);
                                        state.setup.vta.messages.push(MessageType::Info("WebVH update keys created successfully.".to_string()));
                                        state.setup.vta.completed = Completion::CompletedOK;
                                        state.setup.did_keys = Some(persona_keys);
                                    }
                                    Err(e) => {
                                        state.setup.vta.messages.push(MessageType::Error(format!("Failed to create update keys: {e}")));
                                        state.setup.vta.completed = Completion::CompletedFail;
                                    }
                                }
                            }
                            Err(e) => {
                                state.setup.vta.messages.push(MessageType::Error(format!("Failed to create persona keys: {e}")));
                                state.setup.vta.completed = Completion::CompletedFail;
                            }
                        }
                    },
                Action::ExportDIDKeys(export_inputs) => {
                        // Handle exporting DID Keys
                        state.setup.active_page = SetupPage::DidKeysExportShow;
                        state.setup.did_keys_export.messages.push("Starting key export...".to_string());

                        // Send the intial state so that the UX shows the key export page
                        let _ = self.state_tx.send(state.clone());

                        let state_tx_clone = self.state_tx.clone();
                        let mut state_clone = state.clone();
                        let export = tokio::spawn(async move {
                         match export_persona_did_keys(&mut state_clone, &state_tx_clone, export_inputs.username.value(), SecretString::from_str(export_inputs.passphrase.value()).unwrap()) {
                            Ok(export) => {
                                state_clone.setup.did_keys_export.exported =  match export.to_armored_string(ArmorOptions::default()) {
                                    Ok(armored) => Some(armored),
                                    Err(e) => {
                                            state_clone.setup.did_keys_export.messages.push(format!("Error armoring exported keys: {}", e));
                                            None
                                    }
                                };
                            }
                            Err(e) => {
                                    state_clone.setup.did_keys_export.messages.push(format!("Error exporting DID keys: {}", e));
                            }

                        }
                            state_clone.setup.did_keys_export
                        }).await.unwrap();
                        state.setup.did_keys_export = export;
                        if state.setup.did_keys_export.exported.is_some() {
                            state.setup.did_keys_export.messages.push("Key export completed".to_string());
                        }
                    },
                    #[cfg(feature = "openpgp-card")]
                    Action::GetTokens => {
                        // Fetch connected PGP Hardware Tokens
                        state.setup.active_page = SetupPage::TokenSelect;
                        match get_cards() {
                            Ok(cards) => {
                                state.setup.tokens.tokens = cards;
                            }
                            Err(e) => {
                                state.setup.tokens.messages = vec![format!("Error fetching tokens: {}", e)];
                            state.setup.tokens.tokens = vec![];
                            }
                        }
                    },
                #[cfg(feature = "openpgp-card")]
                Action::SetAdminPin(token, admin_pin) => {
                        state.setup.protection = ConfigProtection::Token(token);
                        state.token_admin_pin = Some(admin_pin);
                        state.setup.active_page = SetupPage::TokenFactoryReset;
                    }
                #[cfg(feature = "openpgp-card")]
                Action::FactoryReset(token) => {
                        if let Some(token) = token {
                            state.setup.token_reset.messages.push(MessageType::Info("Starting factory reset...".to_string()));
                            let mut state_clone = state.clone();
                            let reset = tokio::spawn(async move{match factory_reset(token) {
                                    Ok(_) => {
                                        state_clone.setup.token_reset.messages.push(MessageType::Info("Factory reset completed successfully.".to_string()));
                                        state_clone.setup.token_reset.completed_reset = true;
                                    },
                                    Err(e) => state_clone.setup.token_reset.messages.push(MessageType::Error(format!("Factory reset failed: {}", e))),
                                }
                                state_clone.setup.token_reset
                            }).await.unwrap();
                            state.setup.token_reset = reset;
                        } else {
                            state.setup.token_reset.messages.push(MessageType::Error("No token was specified.".to_string()));
                        }
                        state.setup.active_page = SetupPage::TokenFactoryReset;
                    }
                #[cfg(feature = "openpgp-card")]
                Action::TokenWriteKeys(token) => {
                        if let Some(token) = token {
                        let state_tx_clone = self.state_tx.clone();
                            let mut state_clone = state.clone();
                        let result = tokio::spawn(async move{match write_keys_to_card(&mut state_clone, &state_tx_clone, token ) {
                             Ok(_) => {
                                    state_clone.setup.token_reset.messages.push(MessageType::Info("Keys written to token successfully.".to_string()));
                                 state_clone.setup.token_reset.completed_writing = true;
                             }
                             Err(e) => {
                                 state_clone.setup.token_reset.messages.push(MessageType::Error(format!("Error writing keys to token: {}", e)));
                             }
                            }
                                state_clone.setup.token_reset
                        }).await.unwrap();
                            state.setup.token_reset = result;
                        } else {
                            state.setup.token_reset.messages.push(MessageType::Error("No token was specified.".to_string()));
                        }
                    }
                    #[cfg(feature = "openpgp-card")]
                    Action::SetTouchPolicy(token) => {
                        // Called if enabling touch policy
                        state.setup.active_page = SetupPage::TokenSetTouch;
                        if let Some(token) = token {
                           match set_signing_touch_policy(state, &self.state_tx, token) {
                                Ok(_) => state.setup.token_set_touch.completed = true,
                                Err(e) => {
                            state.setup.token_set_touch.messages.push(MessageType::Error(format!("An error occurred when setting touch policy: {e}")));
                                }
                            }
                        } else {
                            state.setup.token_set_touch.messages.push(MessageType::Error("No token was specified.".to_string()));
                        }
                            state.setup.token_set_touch.completed = true;
                    }
                    #[cfg(feature = "openpgp-card")]
                    Action::SetTokenName(token, name) => {
                        // Called if enabling touch policy
                        state.setup.active_page = SetupPage::TokenSetCardholderName;
                        if let Some(token) = token {
                           match set_cardholder_name(state, &self.state_tx, token, &name) {
                                Ok(_) => state.setup.token_cardholder_name.completed = true,
                                Err(e) => {
                            state.setup.token_cardholder_name.messages.push(MessageType::Error(format!("An error occurred when setting cardholder name: {e}")));
                                }
                            }
                        } else {
                            state.setup.token_cardholder_name.messages.push(MessageType::Error("No token was specified.".to_string()));
                        }
                            state.setup.token_cardholder_name.completed = true;
                    }
                    Action::SetCustomMediator(mediator_did) => {
                        // Set the Custom Mediator in setup state
                        state.setup.custom_mediator = Some(mediator_did);
                        state.setup.active_page = SetupPage::UserName;
                    }
                Action::SetUsername(username) => {
                        // Set the username in setup state
                        state.setup.username = username;
                        state.setup.active_page = SetupPage::WebVHAddress;
                    },
                    Action::CreateWebVHDID(webvh_address) => {
                        // Set the WebVH DID in setup state
                        let mut keys = state.setup.did_keys.clone().unwrap();
                        let update_secret = state.setup.vta.update_secret.clone().expect("VTA update secret not set");
                        let next_update_secret = state.setup.vta.next_update_secret.clone().expect("VTA next update secret not set");
                        match create_initial_webvh_did(
                            &webvh_address,
                            &mut keys,
                            state.setup.custom_mediator.as_ref().unwrap_or(&LF_PUBLIC_MEDIATOR_DID.to_string()),
                            update_secret,
                            next_update_secret,
                        ) {
                            Ok((did, document)) => {
                                state.setup.webvh_address.did = did;
                                state.setup.webvh_address.document = document;
                                state.setup.did_keys = Some(keys);
                                state.setup.webvh_address.completed = Completion::CompletedOK;
                                state.setup.webvh_address.messages.push(MessageType::Info("WebVH DID created successfully.".to_string()));
                            },
                            Err(e) => {
                                state.setup.webvh_address.completed = Completion::CompletedFail;
                                state.setup.webvh_address.messages.push(MessageType::Error(format!("Error creating WebVH DID: {e}")));
                            }
                        }
                    },
                    Action::ResetWebVHDID => {
                        // Reset the WebVH DID state
                        state.setup.webvh_address.messages.clear();
                        state.setup.webvh_address.completed = Completion::NotFinished;
                    },
                    Action::ResolveWebVHDID(did) => {
                        // Check if can resolve DID
                        match tdk.did_resolver().resolve(&did).await {
                            Ok(response) => {
                                // Change the key ID's to match the DID VM ID's
                                if let Some(keys) = &mut state.setup.did_keys {
                                    keys.signing.secret.id = [&did, "#key-1"].concat();
                                    keys.authentication.secret.id = [&did, "#key-2"].concat();
                                    keys.decryption.secret.id = [&did, "#key-3"].concat();
                                }

                                state.setup.webvh_address.did = did;
                                state.setup.webvh_address.document = response.doc;
                                state.setup.webvh_address.completed = Completion::CompletedOK;
                                state.setup.webvh_address.messages.push(MessageType::Info("Your DID resolved successfully.".to_string()));
                            },
                            Err(e) => {
                                state.setup.webvh_address.completed = Completion::CompletedFail;
                                state.setup.webvh_address.messages.push(MessageType::Error(format!("Error resolving DID: {e}")));
                            }
                        }
                    }
                    Action::SetupCompleted(setup_flow) => {
                        // Final setup step completed
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
