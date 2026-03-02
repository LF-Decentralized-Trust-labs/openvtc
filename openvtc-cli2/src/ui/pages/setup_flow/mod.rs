#[cfg(feature = "openpgp-card")]
use crate::ui::pages::setup_flow::pgp_token::{
    token_factory_reset::TokenFactoryReset, token_select::TokenSelect,
    token_set_cardholder_name::TokenSetCardholderName, token_set_touch::TokenSetTouch,
    token_start::TokenStart,
};
use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{SetupPage, SetupState},
        state::State,
    },
    ui::{
        component::{Component, ComponentRender},
        pages::setup_flow::{
            config_import::ConfigImport,
            did_keys_export_ask::DIDKeysExportAsk, did_keys_export_inputs::DIDKeysExportInputs,
            did_keys_export_show::DIDKeysExportShow, did_keys_show::DIDKeysShow,
            final_page::FinalPage, mediator_ask::MediatorAsk, mediator_custom::MediatorCustom,
            start_ask::StartAskPanel, unlock_code_ask::UnlockCodeAsk,
            unlock_code_set::UnlockCodeSet, unlock_code_warn::UnlockCodeWarn, username::UserName,
            vta_authenticate::VtaAuthenticate, vta_credential::VtaCredentialPaste,
            vta_keys_fetch::VtaKeysFetch,
            webvh_address::WebvhAddress,
            webvh_server_progress::WebvhServerProgress,
            webvh_server_select::WebvhServerSelect,
        },
    },
};
use crossterm::event::{KeyEvent, KeyEventKind};
use openvtc::colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

pub mod config_import;
pub mod did_keys_export_ask;
pub mod navigation;
pub mod did_keys_export_inputs;
pub mod did_keys_export_show;
pub mod did_keys_show;
pub mod final_page;
pub mod mediator_ask;
pub mod mediator_custom;
pub mod start_ask;
pub mod unlock_code_ask;
pub mod unlock_code_set;
pub mod unlock_code_warn;
pub mod username;
pub mod vta_authenticate;
pub mod vta_credential;
pub mod vta_keys_fetch;
pub mod webvh_address;
pub mod webvh_server_progress;
pub mod webvh_server_select;

#[cfg(feature = "openpgp-card")]
pub mod pgp_token;

/// Handles the Setup Flow sequence
#[derive(Clone)]
pub struct SetupFlow {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    // Local state
    pub start_ask: StartAskPanel,
    pub config_import: ConfigImport,

    pub vta_credential: VtaCredentialPaste,
    pub vta_authenticate: VtaAuthenticate,
    pub vta_keys_fetch: VtaKeysFetch,

    pub did_keys_show: DIDKeysShow,

    pub did_keys_export_ask: DIDKeysExportAsk,
    pub did_keys_export_inputs: DIDKeysExportInputs,
    pub did_keys_export_show: DIDKeysExportShow,

    #[cfg(feature = "openpgp-card")]
    pub token_start: TokenStart,
    #[cfg(feature = "openpgp-card")]
    pub token_select: TokenSelect,
    #[cfg(feature = "openpgp-card")]
    pub token_factory_reset: TokenFactoryReset,
    #[cfg(feature = "openpgp-card")]
    pub token_set_touch: TokenSetTouch,
    #[cfg(feature = "openpgp-card")]
    pub token_set_cardholder_name: TokenSetCardholderName,

    pub unlock_code_ask: UnlockCodeAsk,
    pub unlock_code_warn: UnlockCodeWarn,
    pub unlock_code_set: UnlockCodeSet,

    pub mediator_ask: MediatorAsk,
    pub mediator_custom: MediatorCustom,

    pub username: UserName,

    pub webvh_server_select: WebvhServerSelect,
    pub webvh_server_progress: WebvhServerProgress,

    pub webvh_address: WebvhAddress,

    pub final_page: FinalPage,

    /// State Mapped MainPage Props
    pub props: Props,
}

#[derive(Clone)]
pub struct Props {
    pub state: SetupState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            state: state.setup.clone(),
        }
    }
}

impl Component for SetupFlow {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        SetupFlow {
            action_tx: action_tx.clone(),

            start_ask: StartAskPanel::default(),
            config_import: ConfigImport::default(),
            vta_credential: VtaCredentialPaste::default(),
            vta_authenticate: VtaAuthenticate::default(),
            vta_keys_fetch: VtaKeysFetch::default(),
            did_keys_show: DIDKeysShow::default(),
            did_keys_export_ask: DIDKeysExportAsk::default(),
            did_keys_export_inputs: DIDKeysExportInputs::default(),
            did_keys_export_show: DIDKeysExportShow::default(),

            #[cfg(feature = "openpgp-card")]
            token_start: TokenStart::default(),
            #[cfg(feature = "openpgp-card")]
            token_select: TokenSelect::default(),
            #[cfg(feature = "openpgp-card")]
            token_factory_reset: TokenFactoryReset::default(),
            #[cfg(feature = "openpgp-card")]
            token_set_touch: TokenSetTouch::default(),
            #[cfg(feature = "openpgp-card")]
            token_set_cardholder_name: TokenSetCardholderName::default(),

            unlock_code_ask: UnlockCodeAsk::default(),
            unlock_code_warn: UnlockCodeWarn::default(),
            unlock_code_set: UnlockCodeSet::default(),
            mediator_ask: MediatorAsk::default(),
            mediator_custom: MediatorCustom::default(),
            username: UserName::default(),
            webvh_server_select: WebvhServerSelect::default(),
            webvh_server_progress: WebvhServerProgress::default(),
            webvh_address: WebvhAddress::default(),
            final_page: FinalPage::default(),

            // set the props
            props: Props::from(state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        SetupFlow {
            props: Props::from(state),
            // propagate the update to the child components
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match self.props.state.active_page {
            SetupPage::StartAsk => StartAskPanel::handle_key_event(self, key),
            SetupPage::ConfigImport => ConfigImport::handle_key_event(self, key),
            SetupPage::VtaCredentialPaste => VtaCredentialPaste::handle_key_event(self, key),
            SetupPage::VtaAuthenticate => VtaAuthenticate::handle_key_event(self, key),
            SetupPage::VtaKeysFetch => VtaKeysFetch::handle_key_event(self, key),
            SetupPage::DIDKeysShow => DIDKeysShow::handle_key_event(self, key),
            SetupPage::DidKeysExportAsk => DIDKeysExportAsk::handle_key_event(self, key),
            SetupPage::DidKeysExportInputs => DIDKeysExportInputs::handle_key_event(self, key),
            SetupPage::DidKeysExportShow => DIDKeysExportShow::handle_key_event(self, key),

            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenStart => TokenStart::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSelect => TokenSelect::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenFactoryReset => TokenFactoryReset::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetTouch => TokenSetTouch::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetCardholderName => {
                TokenSetCardholderName::handle_key_event(self, key)
            }

            SetupPage::UnlockCodeAsk => UnlockCodeAsk::handle_key_event(self, key),
            SetupPage::UnlockCodeWarn => UnlockCodeWarn::handle_key_event(self, key),
            SetupPage::UnlockCodeSet => UnlockCodeSet::handle_key_event(self, key),
            SetupPage::MediatorAsk => MediatorAsk::handle_key_event(self, key),
            SetupPage::MediatorCustom => MediatorCustom::handle_key_event(self, key),
            SetupPage::WebvhServerSelect => WebvhServerSelect::handle_key_event(self, key),
            SetupPage::WebvhServerProgress => WebvhServerProgress::handle_key_event(self, key),
            SetupPage::UserName => UserName::handle_key_event(self, key),
            SetupPage::WebVHAddress => WebvhAddress::handle_key_event(self, key),
            SetupPage::FinalPage => FinalPage::handle_key_event(self, key),
        }
    }
}

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for SetupFlow {
    fn render(&self, frame: &mut Frame, _props: ()) {
        match self.props.state.active_page {
            SetupPage::StartAsk => self.start_ask.render(&self.props.state, frame),
            SetupPage::ConfigImport => self.config_import.render(&self.props.state, frame),
            SetupPage::VtaCredentialPaste => {
                self.vta_credential.render(&self.props.state, frame)
            }
            SetupPage::VtaAuthenticate => {
                self.vta_authenticate.render(&self.props.state, frame)
            }
            SetupPage::VtaKeysFetch => self.vta_keys_fetch.render(&self.props.state, frame),
            SetupPage::DIDKeysShow => self.did_keys_show.render(&self.props.state, frame),
            SetupPage::DidKeysExportAsk => {
                self.did_keys_export_ask.render(&self.props.state, frame)
            }
            SetupPage::DidKeysExportInputs => {
                self.did_keys_export_inputs.render(&self.props.state, frame)
            }
            SetupPage::DidKeysExportShow => {
                self.did_keys_export_show.render(&self.props.state, frame)
            }

            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenStart => self.token_start.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSelect => self.token_select.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenFactoryReset => {
                self.token_factory_reset.render(&self.props.state, frame)
            }
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetTouch => self.token_set_touch.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetCardholderName => self
                .token_set_cardholder_name
                .render(&self.props.state, frame),

            SetupPage::UnlockCodeAsk => self.unlock_code_ask.render(&self.props.state, frame),
            SetupPage::UnlockCodeWarn => self.unlock_code_warn.render(&self.props.state, frame),
            SetupPage::UnlockCodeSet => self.unlock_code_set.render(&self.props.state, frame),
            SetupPage::MediatorAsk => self.mediator_ask.render(&self.props.state, frame),
            SetupPage::MediatorCustom => self.mediator_custom.render(&self.props.state, frame),
            SetupPage::WebvhServerSelect => {
                self.webvh_server_select.render(&self.props.state, frame)
            }
            SetupPage::WebvhServerProgress => {
                self.webvh_server_progress.render(&self.props.state, frame)
            }
            SetupPage::UserName => self.username.render(&self.props.state, frame),
            SetupPage::WebVHAddress => self.webvh_address.render(&self.props.state, frame),
            SetupPage::FinalPage => self.final_page.render(&self.props.state, frame),
        }
    }
}

/// Renders the top headline for the setup pages
pub fn render_setup_header(frame: &mut Frame, rect: Rect, state: &SetupState) {
    let mut line1 = Line::default();

    // WebVH-server flow: Get Started → DID & Keys → Profile Security → Display Name → Setup Complete
    // Normal flow:       Get Started → Key Management → Profile Security → Digital Identity → Setup Complete
    let use_server = state.vta.use_webvh_server;
    let total_step: usize = 5;

    // Determine which step we're on
    let active = state.active_page;

    let is_step1 = matches!(active, SetupPage::StartAsk);

    let is_step2_key_mgmt = matches!(
        active,
        SetupPage::VtaCredentialPaste
            | SetupPage::VtaAuthenticate
            | SetupPage::VtaKeysFetch
            | SetupPage::WebvhServerSelect
            | SetupPage::WebvhServerProgress
            | SetupPage::DIDKeysShow
            | SetupPage::DidKeysExportAsk
            | SetupPage::DidKeysExportInputs
            | SetupPage::DidKeysExportShow
    );

    let is_config_import = matches!(active, SetupPage::ConfigImport);

    let is_profile_security = matches!(
        active,
        SetupPage::UnlockCodeAsk | SetupPage::UnlockCodeSet | SetupPage::UnlockCodeWarn
    );
    #[cfg(feature = "openpgp-card")]
    let is_profile_security = is_profile_security
        || matches!(
            active,
            SetupPage::TokenStart
                | SetupPage::TokenSelect
                | SetupPage::TokenFactoryReset
                | SetupPage::TokenSetTouch
                | SetupPage::TokenSetCardholderName
        );

    let is_identity = matches!(
        active,
        SetupPage::MediatorAsk
            | SetupPage::MediatorCustom
            | SetupPage::UserName
            | SetupPage::WebVHAddress
    );

    let is_final = matches!(active, SetupPage::FinalPage);

    // Step labels for each flow
    let steps: Vec<&str> = if use_server {
        vec!["Get Started", "DID & Keys", "Profile Security", "Display Name", "Setup Complete"]
    } else {
        vec!["Get Started", "Key Management", "Profile Security", "Digital Identity", "Setup Complete"]
    };

    // Determine current step index (0-based)
    let current = if is_step1 {
        0
    } else if is_step2_key_mgmt || is_config_import {
        1
    } else if is_profile_security {
        2
    } else if is_identity {
        3
    } else if is_final {
        4
    } else {
        0
    };
    let step = current + 1;

    // Special case: config import has only 2 steps
    let total_step = if is_config_import { 2 } else { total_step };

    // Build the breadcrumb line
    if is_config_import {
        // Config import: just "Get Started → Restore Backup"
        line1.push_span(Span::styled(
            "✓ Get Started",
            Style::new().fg(COLOR_SUCCESS),
        ));
        line1.push_span(Span::styled(" → ", Style::new().fg(COLOR_TEXT_DEFAULT)));
        line1.push_span(Span::styled(
            "● Restore Backup",
            Style::new().fg(COLOR_ORANGE).bold(),
        ));
    } else {
        for (i, label) in steps.iter().enumerate() {
            if i > 0 {
                line1.push_span(Span::styled(" → ", Style::new().fg(COLOR_TEXT_DEFAULT)));
            }
            if i < current {
                line1.push_span(Span::styled(
                    format!("✓ {label}"),
                    Style::new().fg(COLOR_SUCCESS),
                ));
            } else if i == current {
                line1.push_span(Span::styled(
                    format!("● {label}"),
                    Style::new().fg(COLOR_ORANGE).bold(),
                ));
            } else {
                line1.push_span(Span::styled(
                    format!("○ {label}"),
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
        }
    }

    let line2 = Line::from(Span::styled(
        format!("Section {}/{}", step, total_step),
        Style::new().fg(COLOR_BORDER),
    ));

    frame.render_widget(
        Paragraph::new(vec![line2, line1])
            .alignment(Alignment::Left)
            .block(Block::new().padding(Padding::new(2, 0, 0, 0))),
        rect,
    );
}
