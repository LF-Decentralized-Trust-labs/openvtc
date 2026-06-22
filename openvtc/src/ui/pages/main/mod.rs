use crate::colors::{
    COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::{
    state_handler::{
        actions::{Action, CredentialAction, InboxAction, RelationshipAction, SettingsAction},
        main_page::{
            MainPageState, MainPanel,
            content::{ActiveTaskView, InboxConfirm},
            menu::MainMenu,
        },
        state::{ConnectionState, MediatorStatus, State},
    },
    ui::component::{Component, ComponentRender},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use openvtc_core::display::truncate_did_centered;
use ratatui::{
    Frame,
    layout::{
        Alignment,
        Constraint::{Length, Min, Percentage},
        Layout,
    },
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use std::cell::Cell;
use tokio::sync::mpsc::UnboundedSender;

pub mod components;

/// MainPage handles the UI and the state of the primary openvtc interface
pub struct MainPage {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    /// State Mapped MainPage Props
    props: Props,

    /// Secure passphrase buffer — never cloned into State
    passphrase_buffer: String,
    /// Secure confirm passphrase buffer — never cloned into State
    confirm_buffer: String,
    /// Logs panel selected index (local to UI, not in State)
    logs_selected: usize,
    /// Whether the logs panel is showing the detail view of a selected entry
    logs_detail_view: bool,
    /// Vertical scroll offset (in wrapped lines) applied to the content panel.
    /// Mutated by the key handler; clamped at render time.
    content_scroll: u16,
    /// Max reachable scroll offset from the most recent render — written by
    /// render (via `Cell`) and read by the key handler to clamp PageDown/End.
    content_scroll_max: Cell<u16>,
    /// Identifier for the active content view (menu + mode). When it changes
    /// across frames, we reset `content_scroll` so a fresh view starts at top.
    last_view_id: String,
}

/// Number of lines to scroll per PageUp / PageDown press.
const CONTENT_PAGE: u16 = 10;

struct Props {
    main_page: MainPageState,
    connection: ConnectionState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            main_page: state.main_page.clone(),
            connection: state.connection.clone(),
        }
    }
}

impl Component for MainPage {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        MainPage {
            action_tx: action_tx.clone(),
            // set the props
            props: Props::from(state),
            passphrase_buffer: String::new(),
            confirm_buffer: String::new(),
            logs_selected: 0,
            logs_detail_view: false,
            content_scroll: 0,
            content_scroll_max: Cell::new(0),
            last_view_id: view_id(&state.main_page),
        }
        .move_with_state(state)
    }

    fn move_with_state(mut self, state: &State) -> Self
    where
        Self: Sized,
    {
        let new_id = view_id(&state.main_page);
        if new_id != self.last_view_id {
            // Switching menu or mode (e.g. list → detail) starts the new view
            // at the top, even if the previous view was scrolled down.
            self.content_scroll = 0;
            self.last_view_id = new_id;
        }
        self.props = Props::from(state);
        self
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Create-persona overlay: while open it owns all input.
        if self.props.main_page.create_persona.is_some() {
            self.handle_create_persona_key(key);
            return;
        }

        // Add-VIC (import invitation) overlay: while open it owns all input.
        if self.props.main_page.add_vic.is_some() {
            self.handle_add_vic_key(key);
            return;
        }

        // Community switcher overlay (R-C-7): while open it owns all input; while
        // closed, Ctrl+K opens it from anywhere on the main page.
        if self.props.main_page.switcher.is_some() {
            self.handle_switcher_key(key);
            return;
        }
        if key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL) {
            let _ = self.action_tx.send(Action::OpenCommunitySwitcher);
            return;
        }

        // Content panel key handling (when content panel is focused)
        let content_selected = self.props.main_page.content_panel.selected;
        if content_selected && self.handle_content_key_event(key) {
            return;
        }

        match key.code {
            KeyCode::F(10) => {
                let _ = self.action_tx.send(Action::Exit);
            }
            KeyCode::Up if self.props.main_page.menu_panel.selected => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.prev(),
                ));
            }
            KeyCode::Down if self.props.main_page.menu_panel.selected => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.next(),
                ));
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                let next_panel = match self.props.main_page.menu_panel.selected {
                    true => MainPanel::ContentPanel,
                    false => MainPanel::MainMenu,
                };
                let _ = self.action_tx.send(Action::MainPanelSwitch(next_panel));
            }
            KeyCode::Enter => {
                if self.props.main_page.menu_panel.selected_menu == MainMenu::Quit {
                    let _ = self.action_tx.send(Action::Exit);
                } else if self.props.main_page.menu_panel.selected_menu == MainMenu::CreatePersona {
                    // Action item, not a panel: open the overlay (like Quit→Exit).
                    let _ = self.action_tx.send(Action::StartCreatePersona);
                } else if self.props.main_page.menu_panel.selected {
                    let _ = self
                        .action_tx
                        .send(Action::MainPanelSwitch(MainPanel::ContentPanel));
                }
            }
            _ => {}
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        use crate::state_handler::main_page::content::{
            CredentialsMode, RelationshipsMode, SettingsMode,
        };

        // The add-VIC overlay owns paste while open — the operator pastes the VIC
        // JSON straight into the import field (checked before the panel guard).
        if self.props.main_page.add_vic.is_some() {
            let _ = self
                .action_tx
                .send(Action::AddVicPaste(text.trim().to_string()));
            return;
        }

        if !self.props.main_page.content_panel.selected {
            return;
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();
        let trimmed = text.trim();

        match menu {
            MainMenu::Relationships => {
                if let RelationshipsMode::EditAlias { alias_input, .. } =
                    &self.props.main_page.content_panel.relationships.mode
                {
                    let updated = format!("{}{}", alias_input, trimmed);
                    let _ = self.action_tx.send(Action::Relationship(
                        RelationshipAction::EditAliasUpdate(updated),
                    ));
                    return;
                }
                if let RelationshipsMode::NewRequest {
                    did_input,
                    alias_input,
                    reason_input,
                    active_field,
                    ..
                } = &self.props.main_page.content_panel.relationships.mode
                {
                    // Paste into the currently active field
                    let current = match active_field {
                        0 => format!("{}{}", did_input, trimmed),
                        1 => format!("{}{}", alias_input, trimmed),
                        2 => format!("{}{}", reason_input, trimmed),
                        _ => return,
                    };
                    let _ = self.action_tx.send(Action::Relationship(
                        RelationshipAction::InputUpdate {
                            field: *active_field,
                            value: current,
                        },
                    ));
                }
            }
            MainMenu::Credentials => {
                if let CredentialsMode::NewRequest { reason_input, .. } =
                    &self.props.main_page.content_panel.credentials.mode
                {
                    let updated = format!("{}{}", reason_input, trimmed);
                    let _ = self
                        .action_tx
                        .send(Action::Credential(CredentialAction::ReasonUpdate(updated)));
                }
            }
            MainMenu::Settings => {
                match &self.props.main_page.content_panel.settings.mode {
                    SettingsMode::EditFriendlyName { input }
                    | SettingsMode::EditMediatorDid { input }
                    | SettingsMode::EditOrgDid { input } => {
                        let updated = format!("{}{}", input, trimmed);
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FieldUpdate(updated)));
                    }
                    SettingsMode::ExportConfig {
                        path_input,
                        active_field,
                        ..
                    }
                    | SettingsMode::ImportConfig {
                        path_input,
                        active_field,
                        ..
                    } => {
                        if *active_field == 0 {
                            let updated = format!("{}{}", path_input, trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: updated,
                                },
                            ));
                        } else {
                            // Passphrase field — append to secure buffer
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                    }
                    SettingsMode::ChangeProtection { active_field, .. } => {
                        if *active_field == 1 {
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionPassphraseLen(
                                    self.passphrase_buffer.len(),
                                ),
                            ));
                        } else if *active_field == 2 {
                            self.confirm_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// ****************************************************************************
// Content panel key event handling
// ****************************************************************************
impl MainPage {
    /// Handle key events when the content panel is focused.
    /// Returns true if the event was consumed.
    fn handle_content_key_event(&mut self, key: KeyEvent) -> bool {
        // Vertical scroll for the content panel is handled centrally here,
        // before per-menu dispatch, so it works uniformly on every view
        // without conflicting with Up/Down selection bindings.
        match key.code {
            KeyCode::PageUp => {
                let max = self.content_scroll_max.get();
                let cur = self.content_scroll.min(max);
                self.content_scroll = cur.saturating_sub(CONTENT_PAGE);
                return true;
            }
            KeyCode::PageDown => {
                let max = self.content_scroll_max.get();
                self.content_scroll = self.content_scroll.saturating_add(CONTENT_PAGE).min(max);
                return true;
            }
            KeyCode::Home => {
                self.content_scroll = 0;
                return true;
            }
            KeyCode::End => {
                self.content_scroll = self.content_scroll_max.get();
                return true;
            }
            _ => {}
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();

        match menu {
            MainMenu::Inbox => self.handle_inbox_key(key),
            MainMenu::Relationships => self.handle_relationships_key(key),
            MainMenu::Credentials => self.handle_credentials_key(key),
            MainMenu::Settings => self.handle_settings_key(key),
            MainMenu::Logs => self.handle_logs_key(key),
            MainMenu::Help => self.handle_help_key(key),
            MainMenu::Communities => self.handle_communities_key(key),
            MainMenu::Vta => self.handle_vta_key(key),
            _ => false,
        }
    }

    /// VTA Service / DID-manager keys: ↑/↓ move the Context-Identities
    /// selection, `d`/Del removes the selected **orphan** (unbound) DID after a
    /// y/n confirmation. Returns true if consumed.
    fn handle_vta_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::{VicLifecycle, VtaFocus};

        let vta = &self.props.main_page.content_panel.vta;
        let did_count = vta.context_dids.len();
        let did_selected = vta.did_selected_index;
        let focus = vta.focus;
        let vic_count = vta.vics.len();
        let vic_selected = vta.vic_selected_index;
        let vic_lifecycle = vta.vics.get(vic_selected).map(|v| v.lifecycle);

        // VIC purge / delete confirmation gates: only y/Enter confirms.
        if let Some(idx) = vta.confirm_purge_vic {
            let act = match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Action::PurgeVic(idx),
                _ => Action::VicCancelPurge,
            };
            let _ = self.action_tx.send(act);
            return true;
        }
        if let Some(idx) = vta.confirm_delete_vic {
            let act = match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Action::DeleteVic(idx),
                _ => Action::VicCancelDelete,
            };
            let _ = self.action_tx.send(act);
            return true;
        }
        // DID deletion confirmation: only y/Enter confirms; anything else cancels.
        if let Some(idx) = vta.confirm_delete_did {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::DeleteDid(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::DidCancelDelete);
                }
            }
            return true;
        }

        // Keys that apply regardless of which list has focus.
        match key.code {
            KeyCode::Tab => {
                // Switching to the VIC list loads it on demand (no polling).
                if focus == VtaFocus::Dids {
                    let _ = self.action_tx.send(Action::VicRefresh);
                }
                let _ = self.action_tx.send(Action::VicFocusToggle);
                return true;
            }
            KeyCode::Char('n') => {
                // Mint a new standalone persona DID (also on the top-level menu).
                let _ = self.action_tx.send(Action::StartCreatePersona);
                return true;
            }
            KeyCode::Char('a') => {
                let _ = self.action_tx.send(Action::StartAddVic);
                return true;
            }
            KeyCode::Char('i') => {
                let _ = self.action_tx.send(Action::VicToggleInactive);
                return true;
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                return true;
            }
            _ => {}
        }

        // List-scoped keys act on whichever list has focus.
        match focus {
            VtaFocus::Dids => match key.code {
                KeyCode::Up if did_count > 0 => {
                    let _ = self
                        .action_tx
                        .send(Action::DidSelect(did_selected.saturating_sub(1)));
                    true
                }
                KeyCode::Down if did_count > 0 => {
                    let _ = self
                        .action_tx
                        .send(Action::DidSelect((did_selected + 1).min(did_count - 1)));
                    true
                }
                KeyCode::Char('d') | KeyCode::Delete if did_selected < did_count => {
                    // Only orphan (unbound) personas are removable.
                    if vta
                        .context_dids
                        .get(did_selected)
                        .is_some_and(|d| d.bound_communities == 0)
                    {
                        let _ = self.action_tx.send(Action::DidConfirmDelete(did_selected));
                    }
                    true
                }
                _ => false,
            },
            VtaFocus::Vics => match key.code {
                KeyCode::Up if vic_count > 0 => {
                    let _ = self
                        .action_tx
                        .send(Action::VicSelect(vic_selected.saturating_sub(1)));
                    true
                }
                KeyCode::Down if vic_count > 0 => {
                    let _ = self
                        .action_tx
                        .send(Action::VicSelect((vic_selected + 1).min(vic_count - 1)));
                    true
                }
                // r: archive an active VIC (reversible, so no confirm).
                KeyCode::Char('r') if vic_lifecycle == Some(VicLifecycle::Active) => {
                    let _ = self.action_tx.send(Action::VicArchive(vic_selected));
                    true
                }
                // u: unarchive an archived VIC, or restore a soft-deleted one.
                KeyCode::Char('u') => {
                    match vic_lifecycle {
                        Some(VicLifecycle::Archived) => {
                            let _ = self.action_tx.send(Action::VicUnarchive(vic_selected));
                        }
                        Some(VicLifecycle::Deleted) => {
                            let _ = self.action_tx.send(Action::VicRestore(vic_selected));
                        }
                        _ => {}
                    }
                    true
                }
                // d: soft-delete (not already deleted).
                KeyCode::Char('d') | KeyCode::Delete
                    if vic_selected < vic_count
                        && vic_lifecycle != Some(VicLifecycle::Deleted) =>
                {
                    let _ = self.action_tx.send(Action::VicConfirmDelete(vic_selected));
                    true
                }
                // p: irreversible purge.
                KeyCode::Char('p') if vic_selected < vic_count => {
                    let _ = self.action_tx.send(Action::VicConfirmPurge(vic_selected));
                    true
                }
                _ => false,
            },
        }
    }

    /// Communities overview keys (R-A-5 Stage 4): `j` starts the join flow
    /// (incl. from the empty state), ↑/↓ move the selection, `d`/Del removes the
    /// selected community. Returns true if consumed.
    fn handle_communities_key(&mut self, key: KeyEvent) -> bool {
        let comms = &self.props.main_page.content_panel.communities;
        let count = comms.items.len();
        let selected = comms.selected_index;

        // A removal confirmation is pending: only confirm (y/Enter) or cancel
        // (n/Esc) apply; every other key is swallowed so nothing slips through.
        if let Some(idx) = comms.confirm_delete {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::DeleteCommunity(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelDelete);
                }
            }
            return true;
        }
        // A leave confirmation is pending (R-L-1): same y/n gate.
        if let Some(idx) = comms.confirm_leave {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::LeaveCommunity(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelLeave);
                }
            }
            return true;
        }
        // A cancel-pending-join confirmation is pending: same y/n gate.
        if let Some(idx) = comms.confirm_withdraw {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::WithdrawJoin(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelWithdraw);
                }
            }
            return true;
        }

        // Status of the highlighted row gates which management keys apply.
        let sel_active = comms.items.get(selected).is_some_and(|c| c.is_active);
        let sel_inactive = comms.items.get(selected).is_some_and(|c| c.is_inactive);
        let sel_pending = comms.items.get(selected).is_some_and(|c| c.is_pending);

        match key.code {
            KeyCode::Char('j') => {
                let _ = self.action_tx.send(Action::StartJoin);
                true
            }
            KeyCode::Up if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect(selected.saturating_sub(1)));
                true
            }
            KeyCode::Down if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect((selected + 1).min(count - 1)));
                true
            }
            KeyCode::Enter if selected < count => {
                // Make the highlighted community the working context (R-C-6).
                let _ = self.action_tx.send(Action::SetActiveCommunity(selected));
                true
            }
            KeyCode::Char('f') if selected < count => {
                // Toggle the favourite star (R-C-4); the row re-sorts to the top.
                let _ = self.action_tx.send(Action::ToggleFavourite(selected));
                true
            }
            KeyCode::Char('a') if selected < count => {
                // Acknowledge a terminal outcome, clearing its badge (R-S-2).
                let _ = self.action_tx.send(Action::AcknowledgeCommunity(selected));
                true
            }
            KeyCode::Char('l') if sel_active => {
                // Leave an Active community (R-L-1) — arm the y/n confirmation.
                let _ = self.action_tx.send(Action::CommunityConfirmLeave(selected));
                true
            }
            KeyCode::Char('m') if sel_active => {
                // Issue this membership's reciprocal VMC back to the community and
                // send it to the VTC (members/vmc/1.0). Active-only.
                let _ = self.action_tx.send(Action::IssueMemberVmc(selected));
                true
            }
            // Cancel is pending-only: a Pending join can be withdrawn (arming on
            // any other state would only fail downstream, so it's gated).
            KeyCode::Char('c') if sel_pending => {
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmWithdraw(selected));
                true
            }
            KeyCode::Char('x') if sel_inactive => {
                // Archive an inactive community (R-C-8).
                let _ = self.action_tx.send(Action::ArchiveCommunity(selected));
                true
            }
            KeyCode::Char('v') => {
                // Toggle whether archived communities are listed (R-C-8).
                let _ = self.action_tx.send(Action::ToggleShowArchived);
                true
            }
            // Delete is inactive-only (R-C-8): an Active community must be left
            // first. Arming on Active would only fail downstream, so it's gated.
            KeyCode::Char('d') | KeyCode::Delete if sel_inactive => {
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmDelete(selected));
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    /// Create-persona overlay keys. Label phase: Enter mints, Esc cancels,
    /// other keys edit the label. Working phase swallows input. Done/Failed:
    /// `c` re-copies the DID (Done only), Enter/Esc close. Called only while the
    /// overlay is open, where it owns all input.
    fn handle_create_persona_key(&mut self, key: KeyEvent) {
        use crate::state_handler::main_page::content::CreatePersonaPhase;
        let Some(overlay) = self.props.main_page.create_persona.as_ref() else {
            return;
        };
        match overlay.phase {
            CreatePersonaPhase::Label => match key.code {
                KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::CreatePersonaSubmit);
                }
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::CreatePersonaClose);
                }
                _ => {
                    let _ = self.action_tx.send(Action::CreatePersonaInput(key));
                }
            },
            // Mint in progress: lock input (no cancel — the sequence is short and
            // persists atomically).
            CreatePersonaPhase::Working => {}
            CreatePersonaPhase::Done => match key.code {
                KeyCode::Char('c') => {
                    let _ = self.action_tx.send(Action::CreatePersonaCopy);
                }
                _ => {
                    let _ = self.action_tx.send(Action::CreatePersonaClose);
                }
            },
            CreatePersonaPhase::Failed => {
                let _ = self.action_tx.send(Action::CreatePersonaClose);
            }
        }
    }

    /// Add-VIC overlay keys. Input phase: Enter stores, Esc cancels, other keys
    /// edit the paste field. Working swallows input. Done/Failed: any key closes.
    /// Called only while the overlay is open, where it owns all input.
    fn handle_add_vic_key(&mut self, key: KeyEvent) {
        use crate::state_handler::main_page::content::AddVicPhase;
        let Some(overlay) = self.props.main_page.add_vic.as_ref() else {
            return;
        };
        match overlay.phase {
            AddVicPhase::Input => match key.code {
                KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::AddVicSubmit);
                }
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::AddVicClose);
                }
                _ => {
                    let _ = self.action_tx.send(Action::AddVicInput(key));
                }
            },
            AddVicPhase::Working => {}
            AddVicPhase::Done | AddVicPhase::Failed => {
                let _ = self.action_tx.send(Action::AddVicClose);
            }
        }
    }

    /// Community switcher overlay keys (R-C-7): ↑/↓ move the highlight, Enter
    /// switches the working community, Esc (or Ctrl+K again) dismisses. Called
    /// only while the overlay is open, where it owns all input.
    fn handle_switcher_key(&mut self, key: KeyEvent) {
        let Some(switcher) = self.props.main_page.switcher.as_ref() else {
            return;
        };
        let count = switcher.items.len();
        let selected = switcher.selected;
        match key.code {
            KeyCode::Up if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySwitcherMove(selected.saturating_sub(1)));
            }
            KeyCode::Down if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySwitcherMove((selected + 1).min(count - 1)));
            }
            KeyCode::Enter if selected < count => {
                let _ = self.action_tx.send(Action::CommunitySwitcherSelect);
            }
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::CloseCommunitySwitcher);
            }
            KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let _ = self.action_tx.send(Action::CloseCommunitySwitcher);
            }
            _ => {}
        }
    }

    fn handle_inbox_key(&mut self, key: KeyEvent) -> bool {
        let inbox = &self.props.main_page.content_panel.inbox;

        // A destructive-action confirmation is pending: only y/Enter commits;
        // anything else cancels. Mirrors the Communities/VTA-DID pattern (R25).
        if let Some(confirm) = inbox.confirm.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let commit = match confirm {
                        InboxConfirm::Dismiss { task_id } => InboxAction::DismissTask { task_id },
                        InboxConfirm::ClearAll => InboxAction::ClearAll,
                    };
                    let _ = self.action_tx.send(Action::Inbox(commit));
                }
                _ => {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::CancelConfirm));
                }
            }
            return true;
        }

        // If viewing a task detail, handle detail keys
        if let Some(active_task) = &inbox.active_task {
            // Extract what we need before borrowing self mutably
            let task_id = match active_task {
                ActiveTaskView::RelationshipRequestInbound { task_id, .. }
                | ActiveTaskView::VRCRequestInbound { task_id, .. }
                | ActiveTaskView::VRCIssued { task_id, .. }
                | ActiveTaskView::RelationshipRequestOutbound { task_id, .. }
                | ActiveTaskView::VRCRequestOutbound { task_id, .. }
                | ActiveTaskView::Info { task_id, .. } => task_id.clone(),
            };
            let is_rel_inbound = matches!(
                active_task,
                ActiveTaskView::RelationshipRequestInbound { .. }
            );
            let is_vrc_issued = matches!(active_task, ActiveTaskView::VRCIssued { .. });
            let is_vrc_request_inbound =
                matches!(active_task, ActiveTaskView::VRCRequestInbound { .. });

            return match key.code {
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::Inbox(InboxAction::Back));
                    true
                }
                KeyCode::Char('A') if is_rel_inbound => {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::AcceptRelationship {
                            task_id,
                            generate_r_did: true,
                        }));
                    true
                }
                KeyCode::Char('a') => {
                    if is_rel_inbound {
                        let _ =
                            self.action_tx
                                .send(Action::Inbox(InboxAction::AcceptRelationship {
                                    task_id,
                                    generate_r_did: false,
                                }));
                    } else if is_vrc_issued {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::AcceptVrc { task_id }));
                    } else if is_vrc_request_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::AcceptVrcRequest { task_id }));
                    }
                    true
                }
                KeyCode::Char('r') => {
                    if is_rel_inbound {
                        let _ =
                            self.action_tx
                                .send(Action::Inbox(InboxAction::RejectRelationship {
                                    task_id,
                                    reason: None,
                                }));
                    } else if is_vrc_request_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::RejectVrcRequest {
                                task_id,
                                reason: None,
                            }));
                    }
                    true
                }
                KeyCode::Char('d') => {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::ConfirmDismiss { task_id }));
                    true
                }
                _ => false,
            };
        }

        // Task list navigation
        let selected = inbox.selected_index;
        let task_count = inbox.tasks.len();

        match key.code {
            KeyCode::Up if selected > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::SelectTask(selected - 1)));
                true
            }
            KeyCode::Down if selected + 1 < task_count => {
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::SelectTask(selected + 1)));
                true
            }
            KeyCode::Enter if selected < task_count => {
                // All task types have detail views — let the state handler build it
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::OpenDetail(selected)));
                true
            }
            KeyCode::Char('d') if selected < task_count => {
                let task_id = inbox.tasks[selected].id.clone();
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::ConfirmDismiss { task_id }));
                true
            }
            KeyCode::Char('c') if task_count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::ConfirmClearAll));
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    fn handle_relationships_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::RelationshipsMode;

        let rels = &self.props.main_page.content_panel.relationships;

        match &rels.mode {
            RelationshipsMode::NewRequest {
                did_input,
                alias_input,
                reason_input,
                generate_r_did,
                active_field,
            } => {
                // Form input handling
                let active_field = *active_field;
                let generate_r_did = *generate_r_did;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::CancelNewRequest));
                        true
                    }
                    KeyCode::Tab => {
                        // Cycle through fields 0->1->2->3->0
                        let next = (active_field + 1) % 4;
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::FocusField(next)));
                        true
                    }
                    KeyCode::Up if active_field > 0 => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::FocusField(active_field - 1),
                        ));
                        true
                    }
                    KeyCode::Down if active_field < 3 => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::FocusField(active_field + 1),
                        ));
                        true
                    }
                    KeyCode::Char(' ') if active_field == 3 => {
                        // Toggle the generate_r_did boolean
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::ToggleRDid));
                        true
                    }
                    KeyCode::Enter if active_field == 3 => {
                        // Submit from the last field
                        let did = did_input.clone();
                        let alias = alias_input.clone();
                        let reason = if reason_input.trim().is_empty() {
                            None
                        } else {
                            Some(reason_input.clone())
                        };
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::SubmitRequest {
                                did,
                                alias,
                                reason,
                                generate_r_did,
                            },
                        ));
                        true
                    }
                    code if active_field < 3 => {
                        let current = match active_field {
                            0 => did_input,
                            1 => alias_input,
                            _ => reason_input,
                        };
                        match edit_text(code, current) {
                            Some(value) => {
                                let _ = self.action_tx.send(Action::Relationship(
                                    RelationshipAction::InputUpdate {
                                        field: active_field,
                                        value,
                                    },
                                ));
                                true
                            }
                            None => false,
                        }
                    }
                    _ => false,
                }
            }
            RelationshipsMode::Detail {
                index,
                selected_vrc,
            } => {
                let index = *index;
                let current_vrc = *selected_vrc;

                // A removal confirmation is pending: y/Enter commits, anything
                // else cancels. Mirrors the Communities/VTA-DID pattern (R25).
                if let Some(remote_p_did) = rels.confirm_delete.clone() {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Enter => {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::Remove { remote_p_did },
                            ));
                        }
                        _ => {
                            let _ = self
                                .action_tx
                                .send(Action::Relationship(RelationshipAction::CancelRemove));
                        }
                    }
                    return true;
                }

                match key.code {
                    KeyCode::Down => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let total = rel.vrcs_issued.len() + rel.vrcs_received.len();
                            if total > 0 {
                                let next = match current_vrc {
                                    None => Some(0),
                                    Some(n) if n + 1 < total => Some(n + 1),
                                    other => other,
                                };
                                if let RelationshipsMode::Detail {
                                    selected_vrc: ref mut sv,
                                    ..
                                } = self.props.main_page.content_panel.relationships.mode
                                {
                                    *sv = next;
                                }
                            }
                        }
                        true
                    }
                    KeyCode::Up => {
                        let next = match current_vrc {
                            Some(0) => None,
                            Some(n) => Some(n - 1),
                            None => None,
                        };
                        if let RelationshipsMode::Detail {
                            selected_vrc: ref mut sv,
                            ..
                        } = self.props.main_page.content_panel.relationships.mode
                        {
                            *sv = next;
                        }
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::Back));
                        true
                    }
                    KeyCode::Char('e') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let current = rel.alias.clone().unwrap_or_default();
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::StartEditAlias {
                                    index,
                                    current_alias: current,
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('p') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::Ping {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('d') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::ConfirmRemove {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('v') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::RequestVrc {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    _ => false,
                }
            }
            RelationshipsMode::EditAlias { index, alias_input } => {
                let index = *index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::CancelEditAlias { index },
                        ));
                        true
                    }
                    KeyCode::Enter => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::EditAlias {
                                    remote_p_did: rel.remote_p_did.clone(),
                                    alias: alias_input.clone(),
                                },
                            ));
                        }
                        true
                    }
                    code => match edit_text(code, alias_input) {
                        Some(value) => {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::EditAliasUpdate(value),
                            ));
                            true
                        }
                        None => false,
                    },
                }
            }
            RelationshipsMode::List => {
                let selected = rels.selected_index;
                let count = rels.relationships.len();

                match key.code {
                    KeyCode::Up if selected > 0 => {
                        let _ =
                            self.action_tx
                                .send(Action::Relationship(RelationshipAction::Select(
                                    selected - 1,
                                )));
                        true
                    }
                    KeyCode::Down if selected + 1 < count => {
                        let _ =
                            self.action_tx
                                .send(Action::Relationship(RelationshipAction::Select(
                                    selected + 1,
                                )));
                        true
                    }
                    KeyCode::Enter if selected < count => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::OpenDetail(selected),
                        ));
                        true
                    }
                    KeyCode::Char('n') => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::StartNewRequest));
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
        }
    }

    fn handle_credentials_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::{CredentialTab, CredentialsMode};

        let creds = &self.props.main_page.content_panel.credentials;

        match &creds.mode {
            CredentialsMode::NewRequest {
                relationship_index,
                reason_input,
            } => {
                let rel_idx = *relationship_index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::CancelNewRequest));
                        true
                    }
                    KeyCode::Up if rel_idx > 0 => {
                        let _ = self.action_tx.send(Action::Credential(
                            CredentialAction::SelectRelationship(rel_idx - 1),
                        ));
                        true
                    }
                    KeyCode::Down => {
                        // Bound check happens in state handler
                        let _ = self.action_tx.send(Action::Credential(
                            CredentialAction::SelectRelationship(rel_idx + 1),
                        ));
                        true
                    }
                    KeyCode::Enter => {
                        // Get the established relationships from the relationships panel state
                        let established: Vec<_> = self
                            .props
                            .main_page
                            .content_panel
                            .relationships
                            .relationships
                            .iter()
                            .filter(|r| r.state == "Established")
                            .collect();
                        if let Some(rel) = established.get(rel_idx) {
                            let _ = self.action_tx.send(Action::Credential(
                                CredentialAction::SubmitRequest {
                                    relationship_p_did: rel.remote_p_did.clone(),
                                    reason: if reason_input.trim().is_empty() {
                                        None
                                    } else {
                                        Some(reason_input.clone())
                                    },
                                },
                            ));
                        }
                        true
                    }
                    code => match edit_text(code, reason_input) {
                        Some(r) => {
                            let _ = self
                                .action_tx
                                .send(Action::Credential(CredentialAction::ReasonUpdate(r)));
                            true
                        }
                        None => false,
                    },
                }
            }
            CredentialsMode::Detail { index } => {
                let detail_index = *index;

                // A removal confirmation is pending: y/Enter commits, anything
                // else cancels. Mirrors the Communities/VTA-DID pattern (R25).
                if let Some(vrc_id) = creds.confirm_delete.clone() {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Enter => {
                            let _ = self
                                .action_tx
                                .send(Action::Credential(CredentialAction::Remove { vrc_id }));
                        }
                        _ => {
                            let _ = self
                                .action_tx
                                .send(Action::Credential(CredentialAction::CancelRemove));
                        }
                    }
                    return true;
                }

                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Back));
                        true
                    }
                    KeyCode::Char('d') => {
                        let active_list = match creds.selected_tab {
                            CredentialTab::Received => &creds.received,
                            CredentialTab::Issued => &creds.issued,
                            CredentialTab::Membership => &creds.membership,
                        };
                        // Membership/role credentials are community-bound — there
                        // is no local-only removal, so `d` is a no-op there (the
                        // Remove action won't find a matching VRC).
                        if creds.selected_tab != CredentialTab::Membership
                            && let Some(vrc) = active_list.get(detail_index)
                        {
                            let _ = self.action_tx.send(Action::Credential(
                                CredentialAction::ConfirmRemove {
                                    vrc_id: vrc.vrc_id.clone(),
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('c') => {
                        let active_list = match creds.selected_tab {
                            CredentialTab::Received => &creds.received,
                            CredentialTab::Issued => &creds.issued,
                            CredentialTab::Membership => &creds.membership,
                        };
                        if let Some(vrc) = active_list.get(detail_index) {
                            copy_to_clipboard(
                                &vrc.raw_json.to_pretty_json(),
                                "credential",
                                &self.action_tx,
                            );
                        }
                        true
                    }
                    _ => false,
                }
            }
            CredentialsMode::List => {
                let active_list_len = match creds.selected_tab {
                    CredentialTab::Received => creds.received.len(),
                    CredentialTab::Issued => creds.issued.len(),
                    CredentialTab::Membership => creds.membership.len(),
                };
                let selected = creds.selected_index;

                match key.code {
                    KeyCode::Tab => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::SwitchTab));
                        true
                    }
                    KeyCode::Up if selected > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Select(selected - 1)));
                        true
                    }
                    KeyCode::Down if selected + 1 < active_list_len => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Select(selected + 1)));
                        true
                    }
                    KeyCode::Enter if selected < active_list_len => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::OpenDetail(selected)));
                        true
                    }
                    KeyCode::Char('n') => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::StartNewRequest));
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
        }
    }
    fn handle_settings_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::SettingsMode;

        let settings = &self.props.main_page.content_panel.settings;

        match &settings.mode {
            SettingsMode::EditFriendlyName { input }
            | SettingsMode::EditMediatorDid { input }
            | SettingsMode::EditOrgDid { input } => {
                let current = input.clone();
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Enter => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::SubmitEdit {
                                value: current,
                            }));
                        true
                    }
                    code => match edit_text(code, &current) {
                        Some(v) => {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::FieldUpdate(v)));
                            true
                        }
                        None => false,
                    },
                }
            }
            SettingsMode::ExportConfig {
                path_input,
                active_field,
                ..
            } => {
                let active = *active_field;
                let path = path_input.clone();
                self.handle_config_form_key(key, active, path, |path, passphrase| {
                    SettingsAction::ExportConfig { path, passphrase }
                })
            }
            SettingsMode::ChangeProtection {
                selected_option,
                active_field,
                ..
            } => {
                let active = *active_field;
                let sel = *selected_option;
                match key.code {
                    KeyCode::Esc => {
                        self.passphrase_buffer.clear();
                        self.confirm_buffer.clear();
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Up if active == 0 && sel > 0 => {
                        let _ = self.action_tx.send(Action::Settings(
                            SettingsAction::ProtectionOptionSelect(sel - 1),
                        ));
                        true
                    }
                    KeyCode::Down if active == 0 && sel < 1 => {
                        let _ = self.action_tx.send(Action::Settings(
                            SettingsAction::ProtectionOptionSelect(sel + 1),
                        ));
                        true
                    }
                    KeyCode::Enter if active == 0 => {
                        if sel == 0 {
                            // Switch to passphrase input
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::ProtectionStartInput));
                        } else {
                            // Remove passphrase
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::RemovePassphrase));
                        }
                        true
                    }
                    KeyCode::Tab if active >= 1 => {
                        let next = if active == 1 { 2 } else { 1 };
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(next)));
                        true
                    }
                    KeyCode::Up if active == 2 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(1)));
                        true
                    }
                    KeyCode::Down if active == 1 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(2)));
                        true
                    }
                    KeyCode::Enter if active == 2 => {
                        // Submit passphrase
                        if self.passphrase_buffer == self.confirm_buffer
                            && !self.passphrase_buffer.is_empty()
                        {
                            let passphrase = std::mem::take(&mut self.passphrase_buffer);
                            self.confirm_buffer.clear();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::SetPassphrase { passphrase },
                            ));
                        }
                        true
                    }
                    code if active >= 1 => {
                        // Secure passphrase / confirm buffers: apply the keystroke
                        // to the active buffer and report only its length.
                        let buffer = if active == 1 {
                            &mut self.passphrase_buffer
                        } else {
                            &mut self.confirm_buffer
                        };
                        match code {
                            KeyCode::Backspace => {
                                buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                buffer.push(c);
                            }
                            _ => return false,
                        }
                        let len = buffer.len();
                        let action = if active == 1 {
                            SettingsAction::ProtectionPassphraseLen(len)
                        } else {
                            SettingsAction::ProtectionConfirmLen(len)
                        };
                        let _ = self.action_tx.send(Action::Settings(action));
                        true
                    }
                    _ => false,
                }
            }
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenManagement { selected_index } => {
                let sel = *selected_index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::TokenBack));
                        true
                    }
                    KeyCode::Up if sel > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(sel - 1)));
                        true
                    }
                    KeyCode::Down if sel < 1 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(sel + 1)));
                        true
                    }
                    KeyCode::Enter => {
                        match sel {
                            0 => {
                                let _ = self
                                    .action_tx
                                    .send(Action::Settings(SettingsAction::TokenDetect));
                            }
                            1 => {
                                let _ = self
                                    .action_tx
                                    .send(Action::Settings(SettingsAction::TokenFactoryReset));
                            }
                            _ => {}
                        }
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::ImportConfig {
                path_input,
                active_field,
                ..
            } => {
                let active = *active_field;
                let path = path_input.clone();
                self.handle_config_form_key(key, active, path, |path, passphrase| {
                    SettingsAction::ImportConfig { path, passphrase }
                })
            }
            SettingsMode::View => {
                let selected = settings.selected_index;
                // 0=name, 1=mediator, 2=org, 3=persona(ro), 4=protection, 5=export,
                // 6=import, [7=token w/ openpgp-card,] last=wipe.
                #[cfg(feature = "openpgp-card")]
                let token_index: usize = 7;
                #[cfg(feature = "openpgp-card")]
                let wipe_index: usize = 8;
                #[cfg(not(feature = "openpgp-card"))]
                let wipe_index: usize = 7;
                let max_index = wipe_index;

                match key.code {
                    KeyCode::Up if selected > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(selected - 1)));
                        true
                    }
                    KeyCode::Down if selected < max_index => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(selected + 1)));
                        true
                    }
                    KeyCode::Enter => {
                        if selected <= 2 {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        } else if selected == 4 {
                            // Change protection
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::ChangeProtection));
                        } else if selected == 5 {
                            // Export
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        } else if selected == 6 {
                            // Import
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        }
                        #[cfg(feature = "openpgp-card")]
                        if selected == token_index {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::TokenManagement));
                        }
                        if selected == wipe_index {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::WipeProfileStart));
                        }
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::WipeConfirm { confirm_input } => {
                let current = confirm_input.clone();
                match key.code {
                    KeyCode::Esc => {
                        // Drop back to the Settings list — wipe is cancelled.
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Enter => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::WipeProfileConfirm));
                        true
                    }
                    code => match edit_text(code, &current) {
                        Some(next) => {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::WipeProfileInput(next)));
                            true
                        }
                        None => false,
                    },
                }
            }
        }
    }

    /// Shared key handling for the Export/Import config forms. The two forms are
    /// identical except for the submit Action, supplied via `make_submit`
    /// (called with the path and the taken passphrase buffer). `active` is the
    /// focused field (0 = path, 1 = passphrase).
    fn handle_config_form_key(
        &mut self,
        key: KeyEvent,
        active: usize,
        path: String,
        make_submit: impl FnOnce(String, String) -> SettingsAction,
    ) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.passphrase_buffer.clear();
                let _ = self
                    .action_tx
                    .send(Action::Settings(SettingsAction::CancelEdit));
                true
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                let _ = self
                    .action_tx
                    .send(Action::Settings(SettingsAction::FormTabSwitch));
                true
            }
            KeyCode::Enter if active == 1 => {
                let passphrase = std::mem::take(&mut self.passphrase_buffer);
                let _ = self
                    .action_tx
                    .send(Action::Settings(make_submit(path, passphrase)));
                true
            }
            code => {
                if active == 0 {
                    match edit_text(code, &path) {
                        Some(value) => {
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate { field: 0, value },
                            ));
                            true
                        }
                        None => false,
                    }
                } else {
                    match code {
                        KeyCode::Backspace => {
                            self.passphrase_buffer.pop();
                        }
                        KeyCode::Char(c) => {
                            self.passphrase_buffer.push(c);
                        }
                        _ => return false,
                    }
                    let _ = self
                        .action_tx
                        .send(Action::Settings(SettingsAction::PassphraseLen(
                            self.passphrase_buffer.len(),
                        )));
                    true
                }
            }
        }
    }

    fn handle_logs_key(&mut self, key: KeyEvent) -> bool {
        let total = self.props.main_page.activity_log.len();

        // Detail view mode — Esc or Enter to close
        if self.logs_detail_view {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.logs_detail_view = false;
                    return true;
                }
                KeyCode::Char('c') if total > 0 => {
                    let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                    if let Some(entry) = entries.get(self.logs_selected) {
                        copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                    }
                    return true;
                }
                _ => return false,
            }
        }

        match key.code {
            KeyCode::Up if self.logs_selected > 0 => {
                self.logs_selected -= 1;
                true
            }
            KeyCode::Down if self.logs_selected + 1 < total => {
                self.logs_selected += 1;
                true
            }
            KeyCode::Enter if total > 0 => {
                self.logs_detail_view = true;
                true
            }
            KeyCode::Char('c') if total > 0 => {
                // Copy selected log entry to clipboard
                let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                if let Some(entry) = entries.get(self.logs_selected) {
                    copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                }
                true
            }
            KeyCode::Char('a') if total > 0 => {
                // Copy all log entries to clipboard
                let all_text: String = self
                    .props
                    .main_page
                    .activity_log
                    .iter()
                    .rev()
                    .map(|e| e.summary.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&all_text, "All log entries", &self.action_tx);
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('1') => {
                // Copy persona DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .persona_did
                    .clone();
                copy_to_clipboard(&did, "Persona DID", &self.action_tx);
                true
            }
            KeyCode::Char('2') => {
                // Copy mediator DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .mediator_did
                    .clone();
                copy_to_clipboard(&did, "Mediator DID", &self.action_tx);
                true
            }
            KeyCode::Char('3') => {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.did_key_id,
                        "Signing principal (DID#kid)",
                        &self.action_tx,
                    );
                }
                true
            }
            KeyCode::Char('4') => {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.ssh_public_key,
                        "SSH signing public key",
                        &self.action_tx,
                    );
                }
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }
}

/// Apply one text-editing keystroke to `current`, returning the new value when
/// the key edits the buffer, or `None` otherwise. Append-only semantics
/// (printable char appends at the end; Backspace removes the last char) — these
/// inline editors have no cursor, matching the prior behavior exactly.
fn edit_text(code: KeyCode, current: &str) -> Option<String> {
    match code {
        KeyCode::Char(c) => {
            let mut s = current.to_string();
            s.push(c);
            Some(s)
        }
        KeyCode::Backspace => {
            let mut s = current.to_string();
            s.pop();
            Some(s)
        }
        _ => None,
    }
}

/// Stable identifier for the currently-displayed content view, derived from
/// the active menu and its per-panel mode. When this changes across frames
/// (e.g. list → detail, or switching menus), the content panel scroll offset
/// is reset to 0 so the new view starts at the top.
fn view_id(page: &MainPageState) -> String {
    use crate::state_handler::main_page::content::{
        CredentialsMode, RelationshipsMode, SettingsMode,
    };
    let menu = &page.menu_panel.selected_menu;
    let mode: &str = match menu {
        MainMenu::Inbox => {
            if page.content_panel.inbox.active_task.is_some() {
                "detail"
            } else {
                "list"
            }
        }
        MainMenu::Credentials => match &page.content_panel.credentials.mode {
            CredentialsMode::List => "list",
            CredentialsMode::Detail { .. } => "detail",
            CredentialsMode::NewRequest { .. } => "new",
        },
        MainMenu::Relationships => match &page.content_panel.relationships.mode {
            RelationshipsMode::List => "list",
            RelationshipsMode::Detail { .. } => "detail",
            RelationshipsMode::NewRequest { .. } => "new",
            RelationshipsMode::EditAlias { .. } => "edit",
        },
        MainMenu::Settings => match &page.content_panel.settings.mode {
            SettingsMode::View => "view",
            SettingsMode::EditFriendlyName { .. } => "edit-name",
            SettingsMode::EditMediatorDid { .. } => "edit-mediator",
            SettingsMode::EditOrgDid { .. } => "edit-org",
            SettingsMode::ExportConfig { .. } => "export",
            SettingsMode::ImportConfig { .. } => "import",
            SettingsMode::ChangeProtection { .. } => "protect",
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenManagement { .. } => "token",
            SettingsMode::WipeConfirm { .. } => "wipe",
        },
        _ => "",
    };
    format!("{menu:?}:{mode}")
}

/// Copy text to the system clipboard, log the result to the activity log,
/// and update the status panel message to give the user visual feedback.
fn copy_to_clipboard(
    text: &str,
    label: &str,
    action_tx: &tokio::sync::mpsc::UnboundedSender<Action>,
) {
    match crate::clipboard::copy_to_clipboard(text) {
        Ok(method) => {
            tracing::info!(label, method = method.label(), "copied to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                "✓ {label} copied via {}",
                method.label()
            ))));
        }
        Err(e) => {
            tracing::warn!(label, error = %e, "failed to copy to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                "✗ Copy failed: {e}"
            ))));
        }
    }
}

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for MainPage {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let [main_top, main_middle, main_log, main_bottom] =
            Layout::vertical([Length(2), Min(0), Length(8), Length(1)]).areas(frame.area());

        let top =
            Layout::horizontal([Percentage(35), Percentage(30), Percentage(35)]).split(main_top);
        let middle = Layout::horizontal([Percentage(20), Min(0)]).split(main_middle);

        // Top-left: the working community name with a ▾ switcher affordance
        // (R-C-7a), or the dashboard title when there's no active community.
        let community = &self.props.main_page.config.community;
        let top_left = if community.is_empty() {
            Line::from(" OpenVTC Dashboard").fg(COLOR_SUCCESS)
        } else {
            Line::from(vec![
                Span::styled(
                    format!(" {community} "),
                    ratatui::style::Style::default().fg(COLOR_SUCCESS),
                ),
                Span::styled("▾", ratatui::style::Style::default().fg(COLOR_ORANGE)),
            ])
        };
        frame.render_widget(Paragraph::new(top_left).alignment(Alignment::Left), top[0]);

        // Connection status indicator
        let connection_line = match &self.props.connection.status {
            MediatorStatus::Connected => Line::from(Span::styled(
                "Connected",
                ratatui::style::Style::default().fg(COLOR_SUCCESS),
            )),
            MediatorStatus::Connecting => Line::from(Span::styled(
                "Connecting...",
                ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
            )),
            MediatorStatus::Failed(reason) => {
                let display = if reason.len() > 20 {
                    format!("Failed: {}...", &reason[..17])
                } else {
                    format!("Failed: {}", reason)
                };
                Line::from(Span::styled(
                    display,
                    ratatui::style::Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ))
            }
            MediatorStatus::Initializing(step) => Line::from(vec![
                Span::styled(
                    "Initializing: ",
                    ratatui::style::Style::default().fg(COLOR_ORANGE),
                ),
                Span::styled(
                    step.to_string(),
                    ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
                ),
            ]),
            MediatorStatus::Unknown => Line::from(Span::styled(
                "Mediator: --",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
            MediatorStatus::NoActiveCommunity => Line::from(Span::styled(
                "No active community",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
        };
        frame.render_widget(
            Paragraph::new(connection_line).alignment(Alignment::Center),
            top[1],
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(self.props.main_page.config.name.to_string()).fg(COLOR_SUCCESS),
                Line::from(
                    truncate_did_centered(&self.props.main_page.config.did, 30).into_owned(),
                )
                .fg(COLOR_TEXT_DEFAULT),
            ])
            .alignment(Alignment::Right),
            top[2],
        );

        // Middle block
        // Left = menu
        // right = actual content

        // Main Menu
        let inbox_task_count = self.props.main_page.content_panel.inbox.tasks.len();
        self.props
            .main_page
            .menu_panel
            .render(frame, middle[0], inbox_task_count);
        let max_scroll = self.props.main_page.content_panel.render(
            frame,
            middle[1],
            &self.props.main_page.menu_panel,
            &self.props.connection,
            &self.props.main_page.activity_log,
            self.logs_selected,
            self.logs_detail_view,
            self.content_scroll,
        );
        self.content_scroll_max.set(max_scroll);

        // Activity log panel
        let log_block = Block::bordered()
            .merge_borders(MergeStrategy::Fuzzy)
            .fg(COLOR_BORDER)
            .title(" Activity Log ");
        let log_inner = log_block.inner(main_log);
        frame.render_widget(log_block, main_log);

        let log = &self.props.main_page.activity_log;
        let visible_lines = log_inner.height as usize;
        let skip = if log.len() > visible_lines {
            log.len() - visible_lines
        } else {
            0
        };
        let log_lines: Vec<Line> = log
            .iter()
            .skip(skip)
            .map(|entry| Line::from(entry.summary.clone()).dark_gray())
            .collect();
        frame.render_widget(Paragraph::new(log_lines), log_inner);

        // Bottom key hints (single line)
        frame.render_widget(
            Paragraph::new(
                " <TAB> switch panels  <Ctrl+K> switch community  <PgUp/PgDn/Home/End> scroll  <F10> quit",
            )
            .dark_gray()
            .alignment(Alignment::Left),
            main_bottom,
        );

        // Community switcher overlay (R-C-7) floats over everything when open.
        if let Some(switcher) = self.props.main_page.switcher.as_ref() {
            self.render_switcher_overlay(frame, switcher);
        }
        // Create-persona overlay floats over everything when open.
        if let Some(overlay) = self.props.main_page.create_persona.as_ref() {
            self.render_create_persona_overlay(frame, overlay);
        }
        // Add-VIC (import invitation) overlay floats over everything when open.
        if let Some(overlay) = self.props.main_page.add_vic.as_ref() {
            self.render_add_vic_overlay(frame, overlay);
        }
    }
}

impl MainPage {
    /// Render the quick community-switcher popup (R-C-7): a centered overlay
    /// listing the Active communities, the current one marked, the highlighted
    /// one styled. Mirrors the hardware-token overlay's centering pattern.
    fn render_switcher_overlay(
        &self,
        frame: &mut Frame,
        switcher: &crate::state_handler::main_page::content::CommunitySwitcherState,
    ) {
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        // Header + footer (3 lines) plus one line per entry, within bounds.
        let rows = switcher.items.len() as u16;
        // rows + border(2) + padding(2) + blank line + footer line.
        let popup_height = (rows + 6).min(area.height.saturating_sub(2)).max(6);
        let popup_width = 52u16.min(area.width.saturating_sub(4));

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let block = Block::bordered()
            .title(" Switch community ")
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = switcher
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let marker = if i == switcher.selected { "▸ " } else { "  " };
                let current = if item.is_current { "  (active)" } else { "" };
                // Disambiguate multiple memberships of the same community by the
                // presented persona.
                let persona = if item.persona_label.is_empty() {
                    String::new()
                } else {
                    format!("  as {}", item.persona_label)
                };
                let style = if i == switcher.selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };
                Line::from(Span::styled(
                    format!("{marker}{}{persona}{current}", item.display_name),
                    style,
                ))
            })
            .collect();
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "↑/↓ select   ⏎ switch   esc close",
            Style::new().fg(COLOR_BORDER),
        )));

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }

    /// Render the create-persona popup: a centered overlay walking the label
    /// input → progress → result (the DID + copy hint). Mirrors the switcher
    /// overlay's centering pattern.
    fn render_create_persona_overlay(
        &self,
        frame: &mut Frame,
        overlay: &crate::state_handler::main_page::content::CreatePersonaState,
    ) {
        use crate::state_handler::main_page::content::CreatePersonaPhase;
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        let popup_width = 64u16.min(area.width.saturating_sub(4));
        let popup_height = 11u16.min(area.height.saturating_sub(2)).max(7);

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let block = Block::bordered()
            .title(" Create persona DID ")
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = Vec::new();
        match overlay.phase {
            CreatePersonaPhase::Label => {
                lines.push(Line::from(Span::styled(
                    "Label for the new persona:",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )));
                lines.push(Line::from(Span::styled(
                    format!("> {}", overlay.label.value()),
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                )));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "⏎ create   esc cancel",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
            CreatePersonaPhase::Working => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    )));
                }
            }
            CreatePersonaPhase::Done => {
                lines.push(Line::from(Span::styled(
                    "✓ Persona created",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                )));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    overlay.did.clone().unwrap_or_default(),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                )));
                lines.push(Line::default());
                if overlay.copied {
                    lines.push(Line::from(Span::styled(
                        "(copied to clipboard)",
                        Style::new().fg(COLOR_SUCCESS),
                    )));
                }
                lines.push(Line::from(Span::styled(
                    "c: copy again   ⏎/esc close",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
            CreatePersonaPhase::Failed => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    )));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "⏎/esc close",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
        }

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }

    fn render_add_vic_overlay(
        &self,
        frame: &mut Frame,
        overlay: &crate::state_handler::main_page::content::AddVicState,
    ) {
        use crate::state_handler::main_page::content::AddVicPhase;
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        let popup_width = 64u16.min(area.width.saturating_sub(4));
        let popup_height = 11u16.min(area.height.saturating_sub(2)).max(7);

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let block = Block::bordered()
            .title(" Import invitation credential ")
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = Vec::new();
        match overlay.phase {
            AddVicPhase::Input => {
                lines.push(Line::from(Span::styled(
                    "Paste an invitation credential (VIC) JSON, then press ⏎:",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )));
                // The pasted JSON can be long; show a char count + short preview
                // rather than the full body in the popup.
                let val = overlay.input.value();
                let preview = if val.chars().count() > 40 {
                    let head: String = val.chars().take(40).collect();
                    format!("{head}…")
                } else {
                    val.to_string()
                };
                lines.push(Line::from(Span::styled(
                    if val.is_empty() {
                        "> (nothing pasted yet)".to_string()
                    } else {
                        format!("> {preview}   ({} chars)", val.chars().count())
                    },
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                )));
                lines.push(Line::default());
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    )));
                }
                lines.push(Line::from(Span::styled(
                    "⏎ store   esc cancel",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
            AddVicPhase::Working => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    )));
                }
            }
            AddVicPhase::Done => {
                lines.push(Line::from(Span::styled(
                    "✓ Invitation credential stored",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                )));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "⏎/esc close",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
            AddVicPhase::Failed => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    )));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "⏎/esc close",
                    Style::new().fg(COLOR_BORDER),
                )));
            }
        }

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }
}

#[cfg(test)]
mod key_handler_tests {
    //! Key-handler tests for the main page (R26 slice 2): construct a `MainPage`
    //! over a `State`, feed a `KeyEvent` through the public `handle_key_event`
    //! entry point, and assert on the `Action`(s) emitted on the channel. There
    //! is at least one test per content panel, with the R25 destructive-confirm
    //! flow (arm → confirm/cancel) covered for every panel that has one.
    //!
    //! `Action` and its sub-enums derive neither `PartialEq` nor `Debug`, so
    //! assertions pattern-match the expected variant rather than `assert_eq!`.
    use super::*;
    use crate::state_handler::main_page::content::{
        CommunitySummary, CommunitySwitcherState, CredentialTab, CredentialsMode, InboxConfirm,
        RawCredential, RelationshipSummary, RelationshipsMode, SwitcherItem, TaskKind, TaskSummary,
        VrcSummary,
    };
    use crossterm::event::KeyModifiers;
    use std::sync::Arc;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    /// Build a focused `MainPage` on the given menu, after `mutate` populates the
    /// panel state. Returns the page and the receiver to read emitted actions.
    fn page_for(
        menu: MainMenu,
        mutate: impl FnOnce(&mut State),
    ) -> (MainPage, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.main_page.menu_panel.selected_menu = menu;
        // The content panel must be focused for keys to route to its handler.
        state.main_page.content_panel.selected = true;
        mutate(&mut state);
        let page = MainPage::new(&state, tx);
        (page, rx)
    }

    /// A `Press` key event (the only kind `handle_key_event` acts on).
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// A Ctrl-modified `Press` key event.
    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    /// A minimal Communities-panel summary row for key-routing tests.
    fn community_summary(name: &str) -> CommunitySummary {
        community_summary_with(name, true, false, false)
    }

    /// A summary with explicit active/inactive/pending status, for the leave/
    /// cancel/archive/delete key-gating tests.
    fn community_summary_with(
        name: &str,
        is_active: bool,
        is_inactive: bool,
        is_pending: bool,
    ) -> CommunitySummary {
        CommunitySummary {
            display_name: name.to_string(),
            status_label: if is_active { "Active" } else { "Left" }.to_string(),
            persona_label: "persona".to_string(),
            member_since: String::new(),
            favourite: false,
            is_active,
            is_inactive,
            is_pending,
            pending_unacknowledged: false,
            archived: false,
            needs_attention: false,
            persona_did: "did:example:persona".to_string(),
            vtc_did: format!("did:example:{name}"),
            sub_context_id: format!("top/{name}"),
            request_id: String::new(),
            has_membership_credential: false,
            has_role_credential: false,
        }
    }

    fn switcher_item(name: &str, is_current: bool) -> SwitcherItem {
        SwitcherItem {
            vtc_did: format!("did:example:{name}"),
            persona_ref: openvtc_core::config::account::PersonaId::new(),
            display_name: name.to_string(),
            persona_label: String::new(),
            is_current,
        }
    }

    fn rel_summary(remote_p_did: &str) -> RelationshipSummary {
        RelationshipSummary {
            remote_p_did: remote_p_did.to_string(),
            alias: None,
            state: "Established".to_string(),
            our_did: "did:example:me".to_string(),
            remote_did: "did:example:them".to_string(),
            created: String::new(),
            vrcs_issued: Vec::new(),
            vrcs_received: Vec::new(),
        }
    }

    fn vrc_summary(vrc_id: &str) -> VrcSummary {
        VrcSummary {
            vrc_id: vrc_id.to_string(),
            remote_p_did: "did:example:them".to_string(),
            raw_json: RawCredential::Value(Arc::new(serde_json::Value::Null)),
            alias: None,
            issuer: "did:example:issuer".to_string(),
            subject: "did:example:subject".to_string(),
            valid_from: String::new(),
            valid_until: None,
        }
    }

    fn task_summary(id: &str) -> TaskSummary {
        TaskSummary {
            id: id.to_string(),
            type_display: "Trust Ping".to_string(),
            kind: TaskKind::TrustPing,
            remote_did: "did:example:them".to_string(),
            created: String::new(),
        }
    }

    // ----- Communities -------------------------------------------------------

    #[test]
    fn communities_confirm_commits_and_cancels() {
        // y/Enter while a removal is armed commits the delete at that index.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_delete = Some(2);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::DeleteCommunity(2)) => {}
            _ => panic!("expected DeleteCommunity(2)"),
        }

        // Any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_delete = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelDelete) => {}
            _ => panic!("expected CommunityCancelDelete"),
        }
    }

    #[test]
    fn communities_f_toggles_favourite_at_selection() {
        // R-C-4: `f` on the Communities panel stars the highlighted row.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![
                community_summary("a"),
                community_summary("b"),
                community_summary("c"),
            ]
            .into();
            s.main_page.content_panel.communities.selected_index = 1;
        });
        page.handle_key_event(press(KeyCode::Char('f')));
        match rx.try_recv() {
            Ok(Action::ToggleFavourite(1)) => {}
            _ => panic!("expected ToggleFavourite(1)"),
        }
    }

    #[test]
    fn communities_a_acknowledges_at_selection() {
        // R-S-2: `a` on the Communities panel acknowledges the highlighted row.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items =
                vec![community_summary("a"), community_summary("b")].into();
            s.main_page.content_panel.communities.selected_index = 1;
        });
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::AcknowledgeCommunity(1)) => {}
            _ => panic!("expected AcknowledgeCommunity(1)"),
        }
    }

    #[test]
    fn communities_leave_archive_delete_are_status_gated() {
        // Active row: `l` arms a leave; `d`/`x` do nothing (must leave first).
        let active = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", true, false, false)].into();
            })
        };
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('l')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmLeave(0)) => {}
            _ => panic!("expected CommunityConfirmLeave(0)"),
        }
        // Active row: `m` issues this membership's reciprocal VMC to the community.
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('m')));
        match rx.try_recv() {
            Ok(Action::IssueMemberVmc(0)) => {}
            _ => panic!("expected IssueMemberVmc(0)"),
        }
        // Active row: `c` (cancel pending join) does nothing.
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('c')));
        assert!(
            rx.try_recv().is_err(),
            "cancel is gated off for Active rows"
        );
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(
            rx.try_recv().is_err(),
            "delete is gated off for Active rows"
        );
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(
            rx.try_recv().is_err(),
            "archive is gated off for Active rows"
        );

        // Inactive row: `x` archives, `d` arms delete; `l` does nothing.
        let inactive = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", false, true, false)].into();
            })
        };
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('x')));
        match rx.try_recv() {
            Ok(Action::ArchiveCommunity(0)) => {}
            _ => panic!("expected ArchiveCommunity(0)"),
        }
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmDelete(0)) => {}
            _ => panic!("expected CommunityConfirmDelete(0)"),
        }
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('l')));
        assert!(
            rx.try_recv().is_err(),
            "leave is gated off for inactive rows"
        );

        // Pending row: `c` arms a cancel; `d`/`x`/`l` do nothing.
        let pending = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", false, false, true)].into();
            })
        };
        let (mut page, mut rx) = pending();
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmWithdraw(0)) => {}
            _ => panic!("expected CommunityConfirmWithdraw(0)"),
        }
        for (k, what) in [('d', "delete"), ('x', "archive"), ('l', "leave")] {
            let (mut page, mut rx) = pending();
            page.handle_key_event(press(KeyCode::Char(k)));
            assert!(
                rx.try_recv().is_err(),
                "{what} is gated off for pending rows"
            );
        }
    }

    #[test]
    fn communities_leave_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_leave = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::LeaveCommunity(0)) => {}
            _ => panic!("expected LeaveCommunity(0)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_leave = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelLeave) => {}
            _ => panic!("expected CommunityCancelLeave"),
        }
    }

    #[test]
    fn communities_cancel_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_withdraw = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::WithdrawJoin(0)) => {}
            _ => panic!("expected WithdrawJoin(0)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_withdraw = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelWithdraw) => {}
            _ => panic!("expected CommunityCancelWithdraw"),
        }
    }

    #[test]
    fn communities_v_toggles_show_archived() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |_| {});
        page.handle_key_event(press(KeyCode::Char('v')));
        match rx.try_recv() {
            Ok(Action::ToggleShowArchived) => {}
            _ => panic!("expected ToggleShowArchived"),
        }
    }

    // ----- Community switcher overlay (R-C-7) --------------------------------

    #[test]
    fn ctrl_k_opens_switcher() {
        // Ctrl+K opens the quick switcher from the main page (here, no overlay yet).
        let (mut page, mut rx) = page_for(MainMenu::Communities, |_| {});
        page.handle_key_event(ctrl(KeyCode::Char('k')));
        match rx.try_recv() {
            Ok(Action::OpenCommunitySwitcher) => {}
            _ => panic!("expected OpenCommunitySwitcher"),
        }
    }

    #[test]
    fn open_switcher_owns_input_and_navigates() {
        // While the overlay is open it owns all input: ↑/↓ move, Enter switches,
        // Esc and Ctrl+K both close.
        let build = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.switcher = Some(CommunitySwitcherState {
                    items: vec![switcher_item("a", true), switcher_item("b", false)],
                    selected: 0,
                });
            })
        };

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::CommunitySwitcherMove(1)) => {}
            _ => panic!("expected CommunitySwitcherMove(1)"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CommunitySwitcherSelect) => {}
            _ => panic!("expected CommunitySwitcherSelect"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::CloseCommunitySwitcher) => {}
            _ => panic!("expected CloseCommunitySwitcher on Esc"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(ctrl(KeyCode::Char('k')));
        match rx.try_recv() {
            Ok(Action::CloseCommunitySwitcher) => {}
            _ => panic!("expected CloseCommunitySwitcher on Ctrl+K"),
        }
    }

    // ----- VTA / DID manager -------------------------------------------------

    #[test]
    fn vta_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_did = Some(1);
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::DeleteDid(1)) => {}
            _ => panic!("expected DeleteDid(1)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_did = Some(0);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::DidCancelDelete) => {}
            _ => panic!("expected DidCancelDelete"),
        }
    }

    // ----- Create persona ----------------------------------------------------

    #[test]
    fn vta_n_opens_create_persona() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |_| {});
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::StartCreatePersona) => {}
            _ => panic!("expected StartCreatePersona"),
        }
    }

    #[test]
    fn menu_enter_on_create_persona_opens_overlay() {
        // The top-level "Create Persona DID" item is an action, not a panel.
        let (mut page, mut rx) = page_for(MainMenu::CreatePersona, |s| {
            s.main_page.menu_panel.selected = true;
            s.main_page.content_panel.selected = false;
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::StartCreatePersona) => {}
            _ => panic!("expected StartCreatePersona"),
        }
    }

    #[test]
    fn create_persona_label_phase_keys() {
        use crate::state_handler::main_page::content::CreatePersonaState;
        // The open overlay owns all input regardless of the focused panel.
        let open = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.create_persona = Some(CreatePersonaState::default());
            })
        };

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::CreatePersonaInput(_)) => {}
            _ => panic!("expected CreatePersonaInput"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CreatePersonaSubmit) => {}
            _ => panic!("expected CreatePersonaSubmit"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::CreatePersonaClose) => {}
            _ => panic!("expected CreatePersonaClose"),
        }
    }

    #[test]
    fn create_persona_done_phase_keys() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        let done = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.create_persona = Some(CreatePersonaState {
                    phase: CreatePersonaPhase::Done,
                    did: Some("did:webvh:example:alice".to_string()),
                    copied: true,
                    ..Default::default()
                });
            })
        };

        // `c` re-copies; any other key closes.
        let (mut page, mut rx) = done();
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::CreatePersonaCopy) => {}
            _ => panic!("expected CreatePersonaCopy"),
        }

        let (mut page, mut rx) = done();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CreatePersonaClose) => {}
            _ => panic!("expected CreatePersonaClose"),
        }
    }

    // ----- VIC manager -------------------------------------------------------

    use crate::state_handler::main_page::content::{
        AddVicPhase, AddVicState, VicLifecycle, VicSummary, VtaFocus,
    };

    fn vic(id: &str, lifecycle: VicLifecycle) -> VicSummary {
        VicSummary {
            id: id.to_string(),
            issuer: "did:webvh:example:community".to_string(),
            status: "valid".to_string(),
            lifecycle,
            valid_until: String::new(),
        }
    }

    /// Focus the VIC list with the given rows selected at index 0.
    fn vta_vics(rows: Vec<VicSummary>) -> impl Fn(&mut State) {
        move |s: &mut State| {
            let vta = &mut s.main_page.content_panel.vta;
            vta.focus = VtaFocus::Vics;
            vta.vics = rows.clone().into();
            vta.vic_selected_index = 0;
        }
    }

    #[test]
    fn vta_a_opens_add_vic() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |_| {});
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::StartAddVic) => {}
            _ => panic!("expected StartAddVic"),
        }
    }

    #[test]
    fn vta_tab_refreshes_then_toggles_focus() {
        // From the default (Dids) focus, Tab loads the VIC list, then switches.
        let (mut page, mut rx) = page_for(MainMenu::Vta, |_| {});
        page.handle_key_event(press(KeyCode::Tab));
        match rx.try_recv() {
            Ok(Action::VicRefresh) => {}
            _ => panic!("expected VicRefresh first"),
        }
        match rx.try_recv() {
            Ok(Action::VicFocusToggle) => {}
            _ => panic!("expected VicFocusToggle"),
        }
    }

    #[test]
    fn vta_vic_delete_confirm_cycle() {
        // `d` on an active VIC arms the soft-delete confirmation.
        let (mut page, mut rx) =
            page_for(MainMenu::Vta, vta_vics(vec![vic("urn:vic:1", VicLifecycle::Active)]));
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::VicConfirmDelete(0)) => {}
            _ => panic!("expected VicConfirmDelete(0)"),
        }

        // Armed: Enter commits the soft-delete.
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::DeleteVic(0)) => {}
            _ => panic!("expected DeleteVic(0)"),
        }

        // Armed: any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::VicCancelDelete) => {}
            _ => panic!("expected VicCancelDelete"),
        }
    }

    #[test]
    fn vta_vic_purge_confirm_commits() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_purge_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::PurgeVic(0)) => {}
            _ => panic!("expected PurgeVic(0)"),
        }
    }

    #[test]
    fn vta_vic_unarchive_and_restore_by_lifecycle() {
        // `u` on an archived VIC unarchives it.
        let (mut page, mut rx) = page_for(
            MainMenu::Vta,
            vta_vics(vec![vic("urn:vic:1", VicLifecycle::Archived)]),
        );
        page.handle_key_event(press(KeyCode::Char('u')));
        match rx.try_recv() {
            Ok(Action::VicUnarchive(0)) => {}
            _ => panic!("expected VicUnarchive(0)"),
        }

        // `u` on a soft-deleted VIC restores it.
        let (mut page, mut rx) = page_for(
            MainMenu::Vta,
            vta_vics(vec![vic("urn:vic:1", VicLifecycle::Deleted)]),
        );
        page.handle_key_event(press(KeyCode::Char('u')));
        match rx.try_recv() {
            Ok(Action::VicRestore(0)) => {}
            _ => panic!("expected VicRestore(0)"),
        }
    }

    #[test]
    fn add_vic_overlay_input_keys() {
        let open = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.add_vic = Some(AddVicState::default());
            })
        };

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::AddVicSubmit) => {}
            _ => panic!("expected AddVicSubmit"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::AddVicClose) => {}
            _ => panic!("expected AddVicClose"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('x')));
        match rx.try_recv() {
            Ok(Action::AddVicInput(_)) => {}
            _ => panic!("expected AddVicInput"),
        }
    }

    #[test]
    fn add_vic_done_phase_closes() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.add_vic = Some(AddVicState {
                phase: AddVicPhase::Done,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::AddVicClose) => {}
            _ => panic!("expected AddVicClose"),
        }
    }

    #[test]
    fn create_persona_working_phase_swallows_input() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Working,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(
            rx.try_recv().is_err(),
            "the Working phase locks input until the mint resolves"
        );
    }

    // ----- Inbox -------------------------------------------------------------

    #[test]
    fn inbox_d_and_c_arm_confirmation() {
        // `d` on a selected task arms a dismiss confirmation (R25) — it no longer
        // dismisses instantly.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.tasks = Arc::from(vec![task_summary("t1")]);
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ConfirmDismiss { task_id })) => {
                assert_eq!(task_id, "t1");
            }
            _ => panic!("expected Inbox(ConfirmDismiss)"),
        }

        // `c` arms a clear-all confirmation.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.tasks = Arc::from(vec![task_summary("t1")]);
        });
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ConfirmClearAll)) => {}
            _ => panic!("expected Inbox(ConfirmClearAll)"),
        }
    }

    #[test]
    fn inbox_confirm_commits_and_cancels() {
        // A pending dismiss commits on y.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::Dismiss {
                task_id: "t1".to_string(),
            });
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::DismissTask { task_id })) => {
                assert_eq!(task_id, "t1");
            }
            _ => panic!("expected Inbox(DismissTask)"),
        }

        // A pending clear-all commits on Enter.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ClearAll)) => {}
            _ => panic!("expected Inbox(ClearAll)"),
        }

        // Any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::CancelConfirm)) => {}
            _ => panic!("expected Inbox(CancelConfirm)"),
        }
    }

    // ----- Relationships -----------------------------------------------------

    #[test]
    fn relationship_detail_d_arms_then_confirms() {
        // `d` in the detail view arms a removal (R25), carrying the remote DID.
        let (mut page, mut rx) = page_for(MainMenu::Relationships, |s| {
            s.main_page.content_panel.relationships.relationships =
                Arc::from(vec![rel_summary("did:example:partner")]);
            s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index: 0,
                selected_vrc: None,
            };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Relationship(RelationshipAction::ConfirmRemove { remote_p_did })) => {
                assert_eq!(remote_p_did, "did:example:partner");
            }
            _ => panic!("expected Relationship(ConfirmRemove)"),
        }

        // While armed, y commits the Remove.
        let (mut page, mut rx) = page_for(MainMenu::Relationships, |s| {
            s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index: 0,
                selected_vrc: None,
            };
            s.main_page.content_panel.relationships.confirm_delete =
                Some("did:example:partner".to_string());
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Relationship(RelationshipAction::Remove { remote_p_did })) => {
                assert_eq!(remote_p_did, "did:example:partner");
            }
            _ => panic!("expected Relationship(Remove)"),
        }
    }

    // ----- Credentials -------------------------------------------------------

    #[test]
    fn credential_detail_d_arms_then_confirms() {
        // `d` in the detail view arms a removal (R25) on a non-membership tab.
        let (mut page, mut rx) = page_for(MainMenu::Credentials, |s| {
            s.main_page.content_panel.credentials.selected_tab = CredentialTab::Received;
            s.main_page.content_panel.credentials.received = Arc::from(vec![vrc_summary("vrc1")]);
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 0 };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Credential(CredentialAction::ConfirmRemove { vrc_id })) => {
                assert_eq!(vrc_id, "vrc1");
            }
            _ => panic!("expected Credential(ConfirmRemove)"),
        }

        // While armed, y commits the Remove.
        let (mut page, mut rx) = page_for(MainMenu::Credentials, |s| {
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 0 };
            s.main_page.content_panel.credentials.confirm_delete = Some("vrc1".to_string());
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Credential(CredentialAction::Remove { vrc_id })) => {
                assert_eq!(vrc_id, "vrc1");
            }
            _ => panic!("expected Credential(Remove)"),
        }
    }

    // ----- Settings / Logs / Help (one nav test each) ------------------------

    #[test]
    fn settings_view_down_moves_selection() {
        // Default settings mode is View at index 0; Down advances the selection.
        let (mut page, mut rx) = page_for(MainMenu::Settings, |_| {});
        page.handle_key_event(press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::Settings(SettingsAction::Select(1))) => {}
            _ => panic!("expected Settings(Select(1))"),
        }
    }

    #[test]
    fn logs_esc_returns_to_menu() {
        let (mut page, mut rx) = page_for(MainMenu::Logs, |_| {});
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::MainPanelSwitch(MainPanel::MainMenu)) => {}
            _ => panic!("expected MainPanelSwitch(MainMenu)"),
        }
    }

    #[test]
    fn help_esc_returns_to_menu() {
        let (mut page, mut rx) = page_for(MainMenu::Help, |_| {});
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::MainPanelSwitch(MainPanel::MainMenu)) => {}
            _ => panic!("expected MainPanelSwitch(MainMenu)"),
        }
    }
}
