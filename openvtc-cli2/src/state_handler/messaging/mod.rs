use std::sync::Arc;
use std::time::Instant;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use super::state::MediatorStatus;

/// Events sent from the messaging loop to the state handler.
#[derive(Debug, Clone)]
pub enum MessagingEvent {
    TrustPingReceived { from: String },
    TrustPongReceived { from: String, latency_ms: Option<u128> },
    ConnectionStatus(ConnectionStatus),
    InboundMessage { msg_type: String, from: String },
}

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Error(String),
}

/// Validate the mediator connection by sending a trust-ping and measuring latency.
pub async fn validate_mediator_connection(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    mediator_did: &str,
    _persona_did: &str,
) -> Result<u128, Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    TrustPing::default()
        .send_ping(atm, profile, mediator_did, true, true, true)
        .await?;
    let elapsed = start.elapsed().as_millis();

    info!(latency_ms = elapsed, "mediator trust-ping succeeded");
    Ok(elapsed)
}

/// Result of the combined DIDComm init + validation, suitable for sending across tasks.
pub struct ConnInitResult {
    pub atm: Option<Arc<ATM>>,
    pub profile: Option<Arc<ATMProfile>>,
    pub persona_did: String,
    pub status: MediatorStatus,
    pub latency_ms: Option<u128>,
}

/// Combined init + validate that takes owned data so it can run in `tokio::spawn`.
pub async fn init_and_validate(
    shared_state: Arc<TDKSharedState>,
    persona_did: String,
    mediator_did: String,
) -> ConnInitResult {
    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(100)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e} — messaging disabled");
            return ConnInitResult {
                atm: None,
                profile: None,
                persona_did,
                status: MediatorStatus::Failed(format!("ATM config: {e}")),
                latency_ms: None,
            };
        }
    };

    let atm = match ATM::new(atm_config, shared_state).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e} — messaging disabled");
            return ConnInitResult {
                atm: None,
                profile: None,
                persona_did,
                status: MediatorStatus::Failed(format!("ATM init: {e}")),
                latency_ms: None,
            };
        }
    };

    let profile = match ATMProfile::new(
        &atm,
        None,
        persona_did.clone(),
        Some(mediator_did.to_string()),
    )
    .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e} — messaging disabled");
            return ConnInitResult {
                atm: None,
                profile: None,
                persona_did,
                status: MediatorStatus::Failed(format!("ATM profile: {e}")),
                latency_ms: None,
            };
        }
    };

    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable websocket: {e} — messaging disabled");
        return ConnInitResult {
            atm: None,
            profile: None,
            persona_did,
            status: MediatorStatus::Failed(format!("websocket: {e}")),
            latency_ms: None,
        };
    }

    let atm = Arc::new(atm);
    info!("messaging initialized — connected to mediator");

    // Validate with trust-ping (10s timeout)
    let (status, latency_ms) = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        validate_mediator_connection(&atm, &profile, &mediator_did, &persona_did),
    )
    .await
    {
        Ok(Ok(latency_ms)) => (
            MediatorStatus::Connected { latency_ms },
            Some(latency_ms),
        ),
        Ok(Err(e)) => (MediatorStatus::Failed(format!("{e}")), None),
        Err(_) => (
            MediatorStatus::Failed("trust-ping timed out".to_string()),
            None,
        ),
    };

    ConnInitResult {
        atm: Some(atm),
        profile: Some(profile),
        persona_did,
        status,
        latency_ms,
    }
}

/// Run the DIDComm inbound message loop until the interrupt signal fires.
pub async fn run_didcomm_loop(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    persona_did: String,
    event_tx: mpsc::UnboundedSender<MessagingEvent>,
    mut interrupt_rx: broadcast::Receiver<crate::Interrupted>,
) {
    let mut rx: broadcast::Receiver<WebSocketResponses> = match atm.get_inbound_channel() {
        Some(rx) => rx,
        None => {
            warn!("no inbound channel available — messaging disabled");
            return;
        }
    };

    info!("DIDComm message loop started");

    loop {
        tokio::select! {
            result = rx.recv() => {
                let msg = match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => *msg,
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => msg,
                            Err(e) => {
                                warn!("failed to unpack inbound message: {e}");
                                continue;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("inbound message channel lagged, missed {n} messages");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbound message channel closed — stopping message loop");
                        break;
                    }
                };

                dispatch_message(&atm, &profile, &persona_did, &event_tx, &msg).await;
            }
            Ok(_interrupted) = interrupt_rx.recv() => {
                info!("shutdown signal received — stopping DIDComm message loop");
                break;
            }
        }
    }

    atm.graceful_shutdown().await;
    info!("DIDComm message loop stopped");
}

async fn dispatch_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    event_tx: &mpsc::UnboundedSender<MessagingEvent>,
    msg: &Message,
) {
    let msg_type = msg.type_.as_str();
    let from = msg.from.as_deref().unwrap_or("unknown").to_string();

    match msg_type {
        t if t.ends_with("trust-ping/2.0/ping") => {
            debug!(from = %from, "received trust-ping");
            let _ = event_tx.send(MessagingEvent::TrustPingReceived { from: from.clone() });

            // Send pong response
            if let Err(e) = handle_trust_ping(atm, profile, persona_did, msg).await {
                warn!("failed to handle trust-ping: {e}");
            }
        }
        t if t.ends_with("trust-ping/2.0/ping-response") => {
            debug!(from = %from, "received trust-pong");
            let _ = event_tx.send(MessagingEvent::TrustPongReceived {
                from,
                latency_ms: None,
            });
        }
        t if t.ends_with("messagepickup/3.0/status") => {
            // Silently ignore message pickup status
        }
        _ => {
            info!(msg_type = %msg_type, from = %from, "inbound message");
            let _ = event_tx.send(MessagingEvent::InboundMessage {
                msg_type: msg_type.to_string(),
                from,
            });
        }
    }

    // Delete processed message from mediator
    if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
        warn!("failed to delete message from mediator: {e}");
    }
}

async fn handle_trust_ping(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    ping: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or("trust-ping has no 'from' DID — cannot send pong")?;

    let pong = TrustPing::default().generate_pong_message(ping, Some(persona_did))?;

    let (packed, _) = atm
        .pack_encrypted(
            &pong,
            sender_did,
            Some(persona_did),
            Some(persona_did),
            None,
        )
        .await?;

    atm.send_message(profile, &packed, &pong.id, false, false)
        .await?;

    info!(to = sender_did, "sent trust-pong");
    Ok(())
}
