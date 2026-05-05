//! Centralized navigation for the setup wizard flow.
//!
//! All flow-level navigation decisions live here. Individual page files emit
//! a `SetupEvent` and call `handle_nav_result(navigate(..), flow)` instead of
//! directly setting `active_page` or sending `Action`s.

use std::sync::Arc;

use secrecy::SecretBox;

use super::SetupFlow;
use crate::state_handler::{
    actions::Action,
    setup_sequence::{ConfigProtection, SetupPage, SetupState},
};

/// Every page-exit event that requires a flow decision.
pub enum SetupEvent {
    // StartAsk
    CreateNew,
    ImportConfig,

    // VtaProvisioning
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

    // DidGitSignAsk
    DidGitSignAccept,
    DidGitSignSkip,

    // DidGitSignSetup
    DidGitSignDone,

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
        passphrase_hash: Arc<SecretBox<Vec<u8>>>,
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
        SetupEvent::CreateNew => NavResult::GoTo(SetupPage::VtaEnterDid),
        SetupEvent::ImportConfig => NavResult::GoTo(SetupPage::ConfigImport),

        // === VtaProvisioning ===
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
        // Both skip and complete land on the git-signing prompt — the
        // operator chooses there whether to actually run the install.
        SetupEvent::SkipExport => NavResult::GoTo(SetupPage::DidGitSignAsk),
        SetupEvent::StartExport => NavResult::GoTo(SetupPage::DidKeysExportInputs),

        // === DidKeysExportShow ===
        SetupEvent::ExportComplete => NavResult::GoTo(SetupPage::DidGitSignAsk),

        // === DidGitSignAsk ===
        SetupEvent::DidGitSignAccept => NavResult::SendAction(Action::DidGitSignInstall),
        SetupEvent::DidGitSignSkip => NavResult::GoTo(after_export()),

        // === DidGitSignSetup ===
        SetupEvent::DidGitSignDone => NavResult::GoTo(after_export()),

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

#[cfg(test)]
mod tests {
    //! Table-driven tests for the central navigation function. The pure
    //! `(SetupEvent, &SetupState) -> NavResult` shape makes this exhaustive
    //! coverage cheap, and locks in the flow before the larger state-handler
    //! split refactor that's coming next.

    use super::*;

    fn empty_state() -> SetupState {
        SetupState::default()
    }

    fn webvh_state() -> SetupState {
        let mut s = SetupState::default();
        s.vta.use_webvh_server = true;
        s
    }

    fn matches_goto(result: &NavResult, expected: SetupPage) -> bool {
        matches!(result, NavResult::GoTo(p) if std::mem::discriminant(p) == std::mem::discriminant(&expected))
    }

    fn is_send_action(result: &NavResult) -> bool {
        matches!(result, NavResult::SendAction(_))
    }

    fn is_send_then_complete(result: &NavResult) -> bool {
        matches!(result, NavResult::SendActionThenCompleteSetup(_))
    }

    fn is_complete(result: &NavResult) -> bool {
        matches!(result, NavResult::CompleteSetup)
    }

    #[test]
    fn create_new_routes_to_vta_enter_did() {
        let r = navigate(SetupEvent::CreateNew, &empty_state());
        assert!(matches_goto(&r, SetupPage::VtaEnterDid));
    }

    #[test]
    fn import_config_routes_to_config_import() {
        let r = navigate(SetupEvent::ImportConfig, &empty_state());
        assert!(matches_goto(&r, SetupPage::ConfigImport));
    }

    #[test]
    fn vta_auth_completed_routes_to_webvh_when_servers_advertised() {
        use chrono::Utc;
        use vta_sdk::webvh::WebvhServerRecord;
        let mut state = empty_state();
        state.vta.webvh_servers = vec![WebvhServerRecord {
            id: "test-id".to_string(),
            did: "did:webvh:test".to_string(),
            label: Some("test".to_string()),
            access_token: None,
            access_expires_at: None,
            refresh_token: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];
        let r = navigate(SetupEvent::VtaAuthCompleted, &state);
        assert!(matches_goto(&r, SetupPage::WebvhServerSelect));
    }

    #[test]
    fn vta_auth_completed_falls_back_to_create_keys_when_no_server() {
        let r = navigate(SetupEvent::VtaAuthCompleted, &empty_state());
        assert!(is_send_action(&r));
    }

    #[test]
    fn use_webvh_server_emits_create_did_action() {
        let r = navigate(
            SetupEvent::UseWebvhServer {
                server_id: "id".to_string(),
                custom_path: None,
            },
            &empty_state(),
        );
        assert!(is_send_action(&r));
    }

    #[test]
    fn vta_keys_ready_routes_to_did_keys_show() {
        let r = navigate(SetupEvent::VtaKeysReady, &empty_state());
        assert!(matches_goto(&r, SetupPage::DIDKeysShow));
    }

    #[test]
    fn webvh_did_created_routes_to_did_keys_show() {
        let r = navigate(SetupEvent::WebvhDIDCreated, &empty_state());
        assert!(matches_goto(&r, SetupPage::DIDKeysShow));
    }

    #[test]
    fn did_keys_viewed_routes_to_export_ask() {
        let r = navigate(SetupEvent::DIDKeysViewed, &empty_state());
        assert!(matches_goto(&r, SetupPage::DidKeysExportAsk));
    }

    #[test]
    fn skip_export_lands_on_did_git_sign_ask() {
        let r = navigate(SetupEvent::SkipExport, &empty_state());
        assert!(matches_goto(&r, SetupPage::DidGitSignAsk));
    }

    #[test]
    fn start_export_routes_to_export_inputs() {
        let r = navigate(SetupEvent::StartExport, &empty_state());
        assert!(matches_goto(&r, SetupPage::DidKeysExportInputs));
    }

    #[test]
    fn export_complete_lands_on_did_git_sign_ask() {
        let r = navigate(SetupEvent::ExportComplete, &empty_state());
        assert!(matches_goto(&r, SetupPage::DidGitSignAsk));
    }

    #[test]
    fn did_git_sign_accept_emits_install_action() {
        let r = navigate(SetupEvent::DidGitSignAccept, &empty_state());
        assert!(is_send_action(&r));
    }

    #[test]
    fn want_unlock_code_routes_to_unlock_code_set() {
        let r = navigate(SetupEvent::WantUnlockCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeSet));
    }

    #[test]
    fn skip_unlock_code_routes_to_warn() {
        let r = navigate(SetupEvent::SkipUnlockCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeWarn));
    }

    #[test]
    fn return_to_set_code_routes_back_to_unlock_set() {
        let r = navigate(SetupEvent::ReturnToSetCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeSet));
    }

    #[test]
    fn accept_no_code_risk_in_webvh_state_lands_on_username() {
        let r = navigate(SetupEvent::AcceptNoCodeRisk, &webvh_state());
        assert!(matches_goto(&r, SetupPage::UserName));
    }

    #[test]
    fn accept_no_code_risk_in_manual_state_lands_on_mediator() {
        let r = navigate(SetupEvent::AcceptNoCodeRisk, &empty_state());
        assert!(matches_goto(&r, SetupPage::MediatorAsk));
    }

    #[test]
    fn use_default_mediator_routes_to_username() {
        let r = navigate(SetupEvent::UseDefaultMediator, &empty_state());
        assert!(matches_goto(&r, SetupPage::UserName));
    }

    #[test]
    fn use_custom_mediator_routes_to_custom_form() {
        let r = navigate(SetupEvent::UseCustomMediator, &empty_state());
        assert!(matches_goto(&r, SetupPage::MediatorCustom));
    }

    #[test]
    fn custom_mediator_set_emits_action() {
        let r = navigate(
            SetupEvent::CustomMediatorSet {
                mediator_did: "did:web:test".to_string(),
            },
            &empty_state(),
        );
        assert!(is_send_action(&r));
    }

    #[test]
    fn username_set_in_webvh_state_completes_setup() {
        let r = navigate(
            SetupEvent::UsernameSet {
                username: "alice".to_string(),
            },
            &webvh_state(),
        );
        assert!(is_send_then_complete(&r));
    }

    #[test]
    fn username_set_in_manual_state_only_sends_action() {
        let r = navigate(
            SetupEvent::UsernameSet {
                username: "alice".to_string(),
            },
            &empty_state(),
        );
        assert!(is_send_action(&r));
    }

    #[test]
    fn webvh_complete_completes_setup() {
        let r = navigate(SetupEvent::WebVHComplete, &empty_state());
        assert!(is_complete(&r));
    }

    #[test]
    fn setup_done_emits_activate_main_menu() {
        let r = navigate(SetupEvent::SetupDone, &empty_state());
        assert!(is_send_action(&r));
    }

    #[test]
    fn create_manually_emits_create_keys_action() {
        let r = navigate(SetupEvent::CreateManually, &empty_state());
        assert!(is_send_action(&r));
    }
}
