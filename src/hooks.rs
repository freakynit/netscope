//! Language-neutral local WebSocket hook contract.
use crate::events::TrafficEvent;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

pub const HOOK_PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct HookEvent {
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub protocol_version: u8,
    pub request_id: String,
    pub phase: HookPhase,
    pub event: TrafficEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

impl HookEvent {
    pub fn new(
        request_id: String,
        phase: HookPhase,
        event: TrafficEvent,
        body: Option<&[u8]>,
    ) -> Self {
        Self {
            message_type: "event",
            protocol_version: HOOK_PROTOCOL_VERSION,
            request_id,
            phase,
            event,
            body_base64: body.map(|bytes| STANDARD.encode(bytes)),
        }
    }
}

/// Internal action model. Its WebSocket representation uses the stable names required by the
/// public protocol: `continue`, `modify`, `drop`, `respond`, and `delay`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InterceptionAction {
    #[default]
    Continue,
    Drop {
        reason: Option<String>,
    },
    Respond {
        status: Option<u16>,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    },
    Modify {
        set_headers: BTreeMap<String, String>,
        remove_headers: Vec<String>,
        body: Option<Vec<u8>>,
    },
    Delay {
        milliseconds: u64,
    },
}

#[async_trait]
pub trait HookEngine: Send + Sync {
    /// Return promptly. The WebSocket implementation fails open on invalid actions, a timeout,
    /// or a disconnected interceptor.
    async fn decide(
        &self,
        phase: HookPhase,
        event: TrafficEvent,
        body: Option<&[u8]>,
    ) -> InterceptionAction;
    async fn wants_json_bodies(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub struct AllowAll;
#[async_trait]
impl HookEngine for AllowAll {
    async fn decide(&self, _: HookPhase, _: TrafficEvent, _: Option<&[u8]>) -> InterceptionAction {
        InterceptionAction::Continue
    }
}

pub type SharedHookEngine = Arc<dyn HookEngine>;

#[derive(Debug, Clone)]
pub struct WebSocketHookOptions {
    pub listen: SocketAddr,
    pub timeout: Duration,
    pub max_json_body_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct RegisterMessage {
    #[serde(rename = "type")]
    message_type: String,
    protocol_version: u8,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default)]
    body_mode: Option<String>,
}
fn default_role() -> String {
    "intercept".into()
}

#[derive(Debug, Deserialize)]
struct WireAction {
    #[serde(rename = "type")]
    message_type: String,
    request_id: String,
    action: String,
    #[serde(default)]
    set_headers: BTreeMap<String, String>,
    #[serde(default)]
    remove_headers: Vec<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body_base64: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    milliseconds: Option<u64>,
}

struct ActiveClient {
    socket: WebSocketStream<tokio::net::TcpStream>,
    json_bodies: bool,
}
struct HookState {
    interceptor: Option<ActiveClient>,
    observers: Vec<(mpsc::Sender<HookEvent>, bool)>,
    sequence: u64,
}

pub struct WebSocketHookEngine {
    state: Mutex<HookState>,
    timeout: Duration,
    max_json_body_bytes: usize,
}

impl WebSocketHookEngine {
    pub async fn bind(options: WebSocketHookOptions) -> anyhow::Result<Arc<Self>> {
        let listener = TcpListener::bind(options.listen).await?;
        let engine = Arc::new(Self {
            state: Mutex::new(HookState {
                interceptor: None,
                observers: vec![],
                sequence: 0,
            }),
            timeout: options.timeout,
            max_json_body_bytes: options.max_json_body_bytes,
        });
        let accept_engine = engine.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    break;
                };
                let engine = accept_engine.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine.register(stream).await {
                        tracing::debug!(%peer, %error, "hook registration rejected");
                    }
                });
            }
        });
        tracing::info!(address=%options.listen, "hook WebSocket listening");
        Ok(engine)
    }

    async fn register(&self, stream: tokio::net::TcpStream) -> anyhow::Result<()> {
        let mut socket = accept_async(stream).await?;
        let next = timeout(self.timeout, socket.next())
            .await
            .map_err(|_| anyhow::anyhow!("hook registration timed out"))?;
        let message = next.ok_or_else(|| anyhow::anyhow!("hook closed before registering"))??;
        let Message::Text(text) = message else {
            anyhow::bail!("expected JSON registration")
        };
        let registration: RegisterMessage = serde_json::from_str(&text)?;
        if registration.message_type != "register"
            || registration.protocol_version != HOOK_PROTOCOL_VERSION
        {
            anyhow::bail!("unsupported hook registration")
        }
        let json_bodies = registration.body_mode.as_deref() == Some("json");
        socket
            .send(Message::Text(
                serde_json::json!({
                    "type": "registered",
                    "protocol_version": HOOK_PROTOCOL_VERSION,
                    "role": registration.role,
                    "body_mode": if json_bodies { "json" } else { "none" },
                })
                .to_string(),
            ))
            .await?;
        if registration.role == "observe" {
            let (sender, mut receiver) = mpsc::channel(256);
            self.state
                .lock()
                .await
                .observers
                .push((sender, json_bodies));
            tokio::spawn(async move {
                while let Some(event) = receiver.recv().await {
                    let Ok(text) = serde_json::to_string(&event) else {
                        continue;
                    };
                    if socket.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            });
        } else if registration.role == "intercept" {
            self.state.lock().await.interceptor = Some(ActiveClient {
                socket,
                json_bodies,
            });
        } else {
            anyhow::bail!("role must be 'intercept' or 'observe'")
        }
        Ok(())
    }

    fn parse_action(action: WireAction) -> Option<InterceptionAction> {
        if action.message_type != "action" {
            return None;
        }
        let body = action
            .body_base64
            .map(|value| STANDARD.decode(value))
            .transpose()
            .ok()?;
        match action.action.as_str() {
            "continue" => Some(InterceptionAction::Continue),
            "modify" => Some(InterceptionAction::Modify {
                set_headers: action.set_headers,
                remove_headers: action.remove_headers,
                body,
            }),
            "drop" => Some(InterceptionAction::Drop {
                reason: action.reason,
            }),
            "respond" => Some(InterceptionAction::Respond {
                status: action.status,
                headers: if action.headers.is_empty() {
                    action.set_headers
                } else {
                    action.headers
                },
                body: body.unwrap_or_default(),
            }),
            "delay" => Some(InterceptionAction::Delay {
                milliseconds: action.milliseconds.unwrap_or(0),
            }),
            _ => None,
        }
    }
}

#[async_trait]
impl HookEngine for WebSocketHookEngine {
    async fn wants_json_bodies(&self) -> bool {
        let state = self.state.lock().await;
        state
            .interceptor
            .as_ref()
            .is_some_and(|client| client.json_bodies)
            || state.observers.iter().any(|(_, json_bodies)| *json_bodies)
    }

    async fn decide(
        &self,
        phase: HookPhase,
        event: TrafficEvent,
        body: Option<&[u8]>,
    ) -> InterceptionAction {
        let mut state = self.state.lock().await;
        state.sequence += 1;
        let request_id = format!("hook-{}", state.sequence);
        let message = HookEvent::new(request_id.clone(), phase, event, body);
        state
            .observers
            .retain(|(sender, _)| sender.try_send(message.clone()).is_ok());
        let Some(client) = state.interceptor.as_mut() else {
            return InterceptionAction::Continue;
        };
        let result = async {
            let text = serde_json::to_string(&message)?;
            client.socket.send(Message::Text(text)).await?;
            loop {
                let message = client
                    .socket
                    .next()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("hook disconnected"))??;
                let Message::Text(text) = message else {
                    continue;
                };
                let action: WireAction = serde_json::from_str(&text)?;
                if action.request_id == request_id {
                    return Self::parse_action(action)
                        .ok_or_else(|| anyhow::anyhow!("invalid hook action"));
                }
            }
        };
        match timeout(self.timeout, result).await {
            Ok(Ok(action)) => action,
            Ok(Err(error)) => {
                tracing::warn!(%error, "hook failed; continuing traffic");
                state.interceptor = None;
                InterceptionAction::Continue
            }
            Err(_) => {
                tracing::warn!("hook timed out; continuing traffic");
                state.interceptor = None;
                InterceptionAction::Continue
            }
        }
    }
}

impl WebSocketHookEngine {
    pub fn max_json_body_bytes(&self) -> usize {
        self.max_json_body_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_language_neutral_modify_action() {
        let action = WireAction {
            message_type: "action".into(),
            request_id: "hook-1".into(),
            action: "modify".into(),
            set_headers: BTreeMap::from([("x-test".into(), "yes".into())]),
            remove_headers: vec!["server".into()],
            status: None,
            headers: BTreeMap::new(),
            body_base64: Some(STANDARD.encode(br#"{"ok":true}"#)),
            reason: None,
            milliseconds: None,
        };
        assert_eq!(
            WebSocketHookEngine::parse_action(action),
            Some(InterceptionAction::Modify {
                set_headers: BTreeMap::from([("x-test".into(), "yes".into())]),
                remove_headers: vec!["server".into()],
                body: Some(br#"{"ok":true}"#.to_vec()),
            })
        );
    }
}
