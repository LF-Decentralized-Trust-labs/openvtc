#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use openpgp_card::{Card, state::Open};
use openvtc::config::PersonaDIDKeys;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
#[cfg(feature = "openpgp-card")]
use tokio::sync::Mutex;

use crate::{
    Interrupted,
    state_handler::{
        main_page::{MainPanel, menu::MainMenu},
        setup_sequence::{ConfigProtection, SetupPage},
    },
    ui::pages::setup_flow::{SetupFlow, did_keys_export_inputs::DIDKeysExportInputs},
};

pub enum Action {
    Exit,

    /// An unrecoverable error has occurred on the UX Side
    UXError(Interrupted),

    /// Make MainMenu active
    /// This is used from the setup flow to switch back to the main menu
    ActivateMainMenu,

    /// A main menu item has been selected
    MainMenuSelected(MainMenu),

    /// Active Panel switched to
    MainPanelSwitch(MainPanel),

    // ************************************************************************
    // SETUP Pages
    /// Import existing Config
    /// Filename, config_unlock_passphrase, new_unlock_passphrase
    ImportConfig(String, String, String),

    /// How is the Config file protected?
    /// 1. Send the Protection Method
    /// 2. The next page to render
    SetProtection(ConfigProtection, SetupPage),

    /// Sets the DID Persona Keys
    SetDIDKeys(Box<PersonaDIDKeys>),

    /// Export DID Private keys as PGP Armored file
    ExportDIDKeys(DIDKeysExportInputs),

    // ************************************************************************
    // VTA Actions
    /// Submit a VTA credential bundle (base64 encoded)
    VtaSubmitCredential(String),

    /// Authenticate with VTA service
    VtaAuthenticate,

    /// Create keys via VTA service
    VtaCreateKeys,

    // ************************************************************************
    // PGP Hardware token Specific Actions
    /// Fetches PGP Hardware Tokens that are connected
    #[cfg(feature = "openpgp-card")]
    GetTokens,

    /// Set the Admin PIN Code for the Hardware Token
    /// Token ID, Admin PIN
    #[cfg(feature = "openpgp-card")]
    SetAdminPin(String, SecretString),

    /// Set the Touch Policy
    #[cfg(feature = "openpgp-card")]
    SetTouchPolicy(Option<Arc<Mutex<Card<Open>>>>),

    /// Set the Cardholdername
    #[cfg(feature = "openpgp-card")]
    SetTokenName(Option<Arc<Mutex<Card<Open>>>>, String),

    /// Factory Reset Hardware Token
    #[cfg(feature = "openpgp-card")]
    FactoryReset(Option<Arc<Mutex<Card<Open>>>>),

    /// Write Keys
    #[cfg(feature = "openpgp-card")]
    TokenWriteKeys(Option<Arc<Mutex<Card<Open>>>>),

    // ************************************************************************
    /// Using a custom mediator DID
    SetCustomMediator(String),

    /// What username to be known as
    SetUsername(String),

    /// Creates the initial WebVH DID
    CreateWebVHDID(String),

    /// Resets the state of the WebVH DID
    ResetWebVHDID,

    /// Attempts to resolve a WebVH DID
    ResolveWebVHDID(String),

    /// Final setup step completed, sends the whole setup flow
    SetupCompleted(Box<SetupFlow>),
}
