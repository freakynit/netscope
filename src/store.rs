use crate::events::TrafficEvent;
use anyhow::Result;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, broadcast},
};

/// Append-only NDJSON plus a broadcast channel. This is deliberately transport neutral.
#[derive(Clone)]
pub struct EventStore {
    sender: broadcast::Sender<TrafficEvent>,
    file: Option<Arc<Mutex<tokio::fs::File>>>,
}
impl EventStore {
    pub async fn new(path: Option<PathBuf>) -> Result<Self> {
        let (sender, _) = broadcast::channel(2048);
        let file = match path {
            Some(p) => Some(Arc::new(Mutex::new(
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .await?,
            ))),
            None => None,
        };
        Ok(Self { sender, file })
    }
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEvent> {
        self.sender.subscribe()
    }
    pub async fn emit(&self, event: TrafficEvent) {
        if let Some(file) = &self.file
            && let Ok(line) = serde_json::to_vec(&event)
        {
            let mut f = file.lock().await;
            let _ = f.write_all(&line).await;
            let _ = f.write_all(b"\n").await;
        }
        let _ = self.sender.send(event);
    }
}
