//! Credential (VRC) action handlers for the TUI.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::TDK;
use anyhow::Result;
use openvtc_core::{config::Config, logs::LogFamily, tasks::TaskType, vrc::VrcRequest};
use tracing::{debug, info};

/// Send a VRC request to a remote party via an established relationship.
pub async fn send_vrc_request(
    config: &mut Config,
    _tdk: &TDK,
    service: &DIDCommService,
    remote_p_did: &str,
    reason: Option<&str>,
) -> Result<()> {
    let remote_key = Arc::new(remote_p_did.to_string());

    let (our_did, remote_did) = {
        let relationship = config
            .private
            .relationships
            .get(&remote_key)
            .ok_or_else(|| anyhow::anyhow!("No relationship found for {}", remote_p_did))?;
        (
            Arc::clone(&relationship.our_did),
            Arc::clone(&relationship.remote_did),
        )
    };

    let request_body = VrcRequest {
        reason: reason.map(|s| s.to_string()),
    };

    let message = request_body.create_message(&remote_did, &our_did)?;
    let msg_id = Arc::new(message.id.clone());

    super::didcomm::send_message(service, config, &message, &our_did, &remote_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send VRC request: {e}"))?;

    // Create tracking task
    config.private.tasks.new_task(
        &msg_id,
        TaskType::VRCRequestOutbound {
            remote_p_did: remote_key,
        },
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!("Requested VRC from ({}) Task ID ({})", remote_p_did, msg_id),
    );

    info!(to = %remote_p_did, "VRC request sent");
    Ok(())
}

/// Remove a VRC by its ID from both received and issued collections.
pub fn remove_vrc(config: &mut Config, vrc_id: &str) -> Result<()> {
    let vrc_id = Arc::new(vrc_id.to_string());
    config.private.vrcs_received.remove_vrc(&vrc_id);
    config.private.vrcs_issued.remove_vrc(&vrc_id);

    config
        .public
        .logs
        .insert(LogFamily::Task, format!("Removed VRC ({})", vrc_id));

    debug!(vrc_id = %vrc_id, "VRC removed");
    Ok(())
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::CredentialAction,
    dispatch_util, log_did,
    main_page::content::{CredentialTab, CredentialsMode},
    save_coalesce::SaveScheduler,
    state::State,
};

fn handle_switch_tab(state: &mut State) {
    state.main_page.content_panel.credentials.selected_tab =
        match state.main_page.content_panel.credentials.selected_tab {
            CredentialTab::Received => CredentialTab::Issued,
            CredentialTab::Issued => CredentialTab::Membership,
            CredentialTab::Membership => CredentialTab::Received,
        };
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.credentials.selected_index = index;
    state.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index };
}

fn handle_back(state: &mut State) {
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_start_new_request(state: &mut State) {
    state.main_page.content_panel.credentials.mode = CredentialsMode::NewRequest {
        relationship_index: 0,
        reason_input: String::new(),
    };
}

fn handle_select_relationship(state: &mut State, index: usize) {
    if let CredentialsMode::NewRequest {
        ref mut relationship_index,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        let established_count = state
            .main_page
            .content_panel
            .relationships
            .relationships
            .iter()
            .filter(|r| r.state == "Established")
            .count();
        if index < established_count {
            *relationship_index = index;
        }
    }
}

fn handle_reason_update(state: &mut State, value: String) {
    if let CredentialsMode::NewRequest {
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        *reason_input = value;
    }
}

async fn handle_submit_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    save: &mut SaveScheduler,
    relationship_p_did: &str,
    reason: Option<&str>,
) {
    match send_vrc_request(config, tdk, service, relationship_p_did, reason).await {
        Ok(()) => {
            state.main_page.content_panel.credentials.mode = CredentialsMode::List;
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                dispatch_util::Persist::SaveAndSync,
                |mp| &mut mp.content_panel.credentials.status_message,
                format!("VRC request sent to {}", log_did(relationship_p_did)),
                dispatch_util::SyncLog::Plain(format!(
                    "VRC request sent to {}",
                    log_did(relationship_p_did)
                )),
            );
        }
        Err(e) => {
            dispatch_util::record_error(
                &mut state.main_page,
                |mp| &mut mp.content_panel.credentials.status_message,
                "Failed to send VRC request",
                &e,
            );
        }
    }
}

fn handle_remove(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    vrc_id: &str,
) {
    // The confirmation is now resolved.
    state.main_page.content_panel.credentials.confirm_delete = None;
    if let Err(e) = remove_vrc(config, vrc_id) {
        state.main_page.log_error("Failed to remove VRC", &e);
        return;
    }
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.credentials.status_message,
        "VRC removed",
        dispatch_util::SyncLog::Plain("VRC removed".to_string()),
    );
}

/// Dispatch a single `CredentialAction` to its handler.
pub(crate) async fn dispatch(
    action: CredentialAction,
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    save: &mut SaveScheduler,
) {
    match action {
        CredentialAction::SwitchTab => handle_switch_tab(state),
        CredentialAction::Select(index) => {
            state.main_page.content_panel.credentials.selected_index = index;
        }
        CredentialAction::OpenDetail(index) => handle_open_detail(state, index),
        CredentialAction::Back | CredentialAction::CancelNewRequest => handle_back(state),
        CredentialAction::StartNewRequest => handle_start_new_request(state),
        CredentialAction::SelectRelationship(index) => handle_select_relationship(state, index),
        CredentialAction::ReasonUpdate(value) => handle_reason_update(state, value),
        CredentialAction::SubmitRequest {
            relationship_p_did,
            reason,
        } => {
            handle_submit_request(
                config,
                tdk,
                service,
                state,
                save,
                &relationship_p_did,
                reason.as_deref(),
            )
            .await
        }
        CredentialAction::Remove { vrc_id } => handle_remove(config, state, save, &vrc_id),
        // R25 confirmation arming/cancel — pure state mutations.
        CredentialAction::ConfirmRemove { vrc_id } => {
            state.main_page.content_panel.credentials.confirm_delete = Some(vrc_id);
        }
        CredentialAction::CancelRemove => {
            state.main_page.content_panel.credentials.confirm_delete = None;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Table-driven tests for the pure mode-transition handlers in this module.
    //! Each is a pure function of `&mut State`; the tables drive the handler from
    //! a starting `State` and assert on the resulting credentials-panel mode/tab.
    //! Mirrors the table-test style in `ui/pages/setup_flow/navigation.rs`.
    use super::*;

    /// `handle_switch_tab` cycles Received → Issued → Membership → Received and
    /// resets the selection index each time.
    #[test]
    fn switch_tab_cycles_and_resets_index() {
        // (starting tab, expected next tab)
        let cases: &[(CredentialTab, CredentialTab)] = &[
            (CredentialTab::Received, CredentialTab::Issued),
            (CredentialTab::Issued, CredentialTab::Membership),
            (CredentialTab::Membership, CredentialTab::Received),
        ];
        for (start, expected) in cases {
            let mut state = State::default();
            state.main_page.content_panel.credentials.selected_tab = *start;
            state.main_page.content_panel.credentials.selected_index = 5;
            handle_switch_tab(&mut state);
            assert_eq!(
                state.main_page.content_panel.credentials.selected_tab, *expected,
                "from {start:?}"
            );
            assert_eq!(
                state.main_page.content_panel.credentials.selected_index, 0,
                "index reset on tab switch from {start:?}"
            );
        }
    }

    /// `handle_open_detail` enters `Detail { index }` and tracks the index;
    /// `handle_back` returns to `List` resetting the index.
    #[test]
    fn open_detail_and_back_transitions() {
        for index in [0usize, 3, 42] {
            let mut state = State::default();
            handle_open_detail(&mut state, index);
            assert!(
                matches!(
                    state.main_page.content_panel.credentials.mode,
                    CredentialsMode::Detail { index: i } if i == index
                ),
                "open_detail({index}) enters Detail"
            );
            assert_eq!(
                state.main_page.content_panel.credentials.selected_index,
                index
            );

            handle_back(&mut state);
            assert!(
                matches!(
                    state.main_page.content_panel.credentials.mode,
                    CredentialsMode::List
                ),
                "back returns to List"
            );
            assert_eq!(state.main_page.content_panel.credentials.selected_index, 0);
        }
    }

    /// `handle_start_new_request` enters the `NewRequest` form with a zeroed
    /// relationship index and an empty reason.
    #[test]
    fn start_new_request_enters_form() {
        let mut state = State::default();
        handle_start_new_request(&mut state);
        match &state.main_page.content_panel.credentials.mode {
            CredentialsMode::NewRequest {
                relationship_index,
                reason_input,
            } => {
                assert_eq!(*relationship_index, 0);
                assert!(reason_input.is_empty());
            }
            other => panic!("expected NewRequest, got {other:?}"),
        }
    }

    /// `handle_reason_update` writes the reason only while in `NewRequest`, and is
    /// a no-op in other modes. Table-driven over the starting mode.
    #[test]
    fn reason_update_only_in_new_request() {
        // In NewRequest: the reason is written.
        let mut state = State::default();
        handle_start_new_request(&mut state);
        handle_reason_update(&mut state, "because".to_string());
        assert!(matches!(
            &state.main_page.content_panel.credentials.mode,
            CredentialsMode::NewRequest { reason_input, .. } if reason_input == "because"
        ));

        // In List / Detail: a no-op (mode unchanged).
        for mode in [CredentialsMode::List, CredentialsMode::Detail { index: 1 }] {
            let mut state = State::default();
            state.main_page.content_panel.credentials.mode = mode.clone();
            handle_reason_update(&mut state, "ignored".to_string());
            assert_eq!(
                std::mem::discriminant(&state.main_page.content_panel.credentials.mode),
                std::mem::discriminant(&mode),
                "reason_update is a no-op outside NewRequest"
            );
        }
    }
}
