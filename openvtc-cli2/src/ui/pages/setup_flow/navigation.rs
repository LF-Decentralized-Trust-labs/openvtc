//! Centralized navigation for the setup wizard flow.
//!
//! All flow-level navigation decisions live here. Individual page files emit
//! a `SetupEvent` and call `handle_nav_result(navigate(..), flow)` instead of
//! directly setting `active_page` or sending `Action`s.

use std::sync::Arc;

use secrecy::SecretVec;

use crate::state_handler::{
    actions::Action,
    setup_sequence::{ConfigProtection, SetupPage, SetupState},
};
use super::SetupFlow;

/// Every page-exit event that requires a flow decision.
pub enum SetupEvent {
    // StartAsk
    CreateNew,
    ImportConfig,

    // VtaAuthenticate
    VtaAuthCompleted,

    // WebvhServerSelect
    UseWebvhServer {
        server_id: String,
        custom_path: Option<String>,
    },
    CreateManually,

    // VtaKeysFetch
    VtaKeysReady,

    // WebvhServerProgress
    WebvhDIDCreated,

    // DIDKeysShow
    DIDKeysViewed,

    // DidKeysExportAsk / DidKeysExportShow
    SkipExport,
    StartExport,
    ExportComplete,

    // Token pages (cfg-gated)
    #[cfg(feature = "openpgp-card")]
    TokenSkipped,
    #[cfg(feature = "openpgp-card")]
    TokenNoSelection,
    #[cfg(feature = "openpgp-card")]
    TokenWritingComplete,
    #[cfg(feature = "openpgp-card")]
    TokenTouchComplete,
    #[cfg(feature = "openpgp-card")]
    TokenNameDone,
    #[cfg(feature = "openpgp-card")]
    TokenNameSkipped,

    // UnlockCode
    WantUnlockCode,
    SkipUnlockCode,
    UnlockCodeSet {
        passphrase_hash: Arc<SecretVec<u8>>,
    },
    ReturnToSetCode,
    AcceptNoCodeRisk,

    // Mediator
    UseDefaultMediator,
    UseCustomMediator,
    CustomMediatorSet {
        mediator_did: String,
    },

    // UserName
    UsernameSet {
        username: String,
    },

    // WebVHAddress
    WebVHComplete,

    // FinalPage
    SetupDone,
}

/// What should happen after a navigation decision.
#[allow(dead_code)]
pub enum NavResult {
    /// Navigate to a specific page.
    GoTo(SetupPage),
    /// Send an action to the backend.
    SendAction(Action),
    /// Send SetupCompleted (needs flow.clone()).
    CompleteSetup,
    /// Send an action, then send SetupCompleted.
    SendActionThenCompleteSetup(Action),
    /// Do nothing.
    None,
}

/// Central navigation function — all conditional flow logic lives here.
pub fn navigate(event: SetupEvent, state: &SetupState) -> NavResult {
    match event {
        // === StartAsk ===
        SetupEvent::CreateNew => NavResult::GoTo(SetupPage::VtaCredentialPaste),
        SetupEvent::ImportConfig => NavResult::GoTo(SetupPage::ConfigImport),

        // === VtaAuthenticate ===
        SetupEvent::VtaAuthCompleted => {
            if !state.vta.webvh_servers.is_empty() {
                NavResult::GoTo(SetupPage::WebvhServerSelect)
            } else {
                NavResult::SendAction(Action::VtaCreateKeys)
            }
        }

        // === WebvhServerSelect ===
        SetupEvent::UseWebvhServer {
            server_id,
            custom_path,
        } => NavResult::SendAction(Action::WebvhServerCreateDid(server_id, custom_path)),
        SetupEvent::CreateManually => NavResult::SendAction(Action::VtaCreateKeys),

        // === VtaKeysFetch ===
        SetupEvent::VtaKeysReady => NavResult::GoTo(SetupPage::DIDKeysShow),

        // === WebvhServerProgress ===
        SetupEvent::WebvhDIDCreated => NavResult::GoTo(SetupPage::DIDKeysShow),

        // === DIDKeysShow ===
        SetupEvent::DIDKeysViewed => NavResult::GoTo(SetupPage::DidKeysExportAsk),

        // === DidKeysExportAsk ===
        SetupEvent::SkipExport => NavResult::GoTo(after_export()),
        SetupEvent::StartExport => NavResult::GoTo(SetupPage::DidKeysExportInputs),

        // === DidKeysExportShow ===
        SetupEvent::ExportComplete => NavResult::GoTo(after_export()),

        // === Token pages ===
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenSkipped => NavResult::GoTo(SetupPage::UnlockCodeAsk),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenNoSelection => NavResult::GoTo(SetupPage::UnlockCodeAsk),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenWritingComplete => NavResult::GoTo(SetupPage::TokenSetTouch),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenTouchComplete => NavResult::GoTo(SetupPage::TokenSetCardholderName),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenNameDone | SetupEvent::TokenNameSkipped => {
            NavResult::GoTo(after_tokens(state))
        }

        // === UnlockCode ===
        SetupEvent::WantUnlockCode => NavResult::GoTo(SetupPage::UnlockCodeSet),
        SetupEvent::SkipUnlockCode => NavResult::GoTo(SetupPage::UnlockCodeWarn),
        SetupEvent::UnlockCodeSet { passphrase_hash } => {
            let next = after_unlock(state);
            NavResult::SendAction(Action::SetProtection(
                ConfigProtection::Passcode(passphrase_hash),
                next,
            ))
        }
        SetupEvent::ReturnToSetCode => NavResult::GoTo(SetupPage::UnlockCodeSet),
        SetupEvent::AcceptNoCodeRisk => NavResult::GoTo(after_unlock(state)),

        // === Mediator ===
        SetupEvent::UseDefaultMediator => NavResult::GoTo(SetupPage::UserName),
        SetupEvent::UseCustomMediator => NavResult::GoTo(SetupPage::MediatorCustom),
        SetupEvent::CustomMediatorSet { mediator_did } => {
            NavResult::SendAction(Action::SetCustomMediator(mediator_did))
        }

        // === UserName ===
        SetupEvent::UsernameSet { username } => {
            if state.vta.use_webvh_server {
                NavResult::SendActionThenCompleteSetup(Action::SetUsername(username))
            } else {
                NavResult::SendAction(Action::SetUsername(username))
            }
        }

        // === WebVHAddress ===
        SetupEvent::WebVHComplete => NavResult::CompleteSetup,

        // === FinalPage ===
        SetupEvent::SetupDone => NavResult::SendAction(Action::ActivateMainMenu),
    }
}

/// After export (skip or complete), go to token setup or unlock code.
fn after_export() -> SetupPage {
    #[cfg(feature = "openpgp-card")]
    {
        SetupPage::TokenStart
    }
    #[cfg(not(feature = "openpgp-card"))]
    {
        SetupPage::UnlockCodeAsk
    }
}

/// After token setup is done, go to unlock code.
#[cfg(feature = "openpgp-card")]
fn after_tokens(state: &SetupState) -> SetupPage {
    let _ = state; // tokens always lead to UnlockCodeAsk
    SetupPage::UnlockCodeAsk
}

/// After unlock code (set or skipped), go to UserName (webvh) or MediatorAsk (manual).
fn after_unlock(state: &SetupState) -> SetupPage {
    if state.vta.use_webvh_server {
        SetupPage::UserName
    } else {
        SetupPage::MediatorAsk
    }
}

/// Executes a `NavResult` against the setup flow.
pub fn handle_nav_result(result: NavResult, flow: &mut SetupFlow) {
    match result {
        NavResult::GoTo(page) => {
            flow.props.state.active_page = page;
        }
        NavResult::SendAction(action) => {
            let _ = flow.action_tx.send(action);
        }
        NavResult::CompleteSetup => {
            let _ = flow
                .action_tx
                .send(Action::SetupCompleted(Box::new(flow.clone())));
        }
        NavResult::SendActionThenCompleteSetup(action) => {
            let _ = flow.action_tx.send(action);
            let _ = flow
                .action_tx
                .send(Action::SetupCompleted(Box::new(flow.clone())));
        }
        NavResult::None => {}
    }
}
