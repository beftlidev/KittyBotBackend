use crate::ipc_server::{
    broadcast_to_all_clients, get_connected_clients, ConnectedClients, SocketMessage,
};
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};

type PendingRequests = Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>;

lazy_static::lazy_static! {
    static ref PENDING_REQUESTS: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
}

pub async fn get_bot_stats(State(connected_clients): State<ConnectedClients>) -> Json<Value> {
    let clients = get_connected_clients(&connected_clients).await;

    if clients.is_empty() {
        return Json(json!({
            "ok": false,
            "message": "No bot clients connected",
            "data": null
        }));
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();

    {
        let mut pending = PENDING_REQUESTS.lock().await;
        pending.insert(request_id.clone(), tx);
    }

    let bot_stats_message = SocketMessage {
        event: "botStats".to_string(),
        data: json!({
            "timestamp": chrono::Utc::now().timestamp(),
            "request_id": request_id
        }),
    };

    let failed_clients = broadcast_to_all_clients(&connected_clients, bot_stats_message).await;

    if !failed_clients.is_empty() {
        let mut pending = PENDING_REQUESTS.lock().await;
        pending.remove(&request_id);
        return Json(json!({
            "ok": false,
            "message": "Failed to send to some clients",
            "failed_clients": failed_clients
        }));
    }

    match timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(bot_data)) => Json(json!({
            "ok": true,
            "message": "Bot stats received successfully",
            "data": bot_data
        })),
        Ok(Err(_)) => Json(json!({
            "ok": false,
            "message": "Internal error receiving bot stats",
            "data": null
        })),
        Err(_) => {
            let mut pending = PENDING_REQUESTS.lock().await;
            pending.remove(&request_id);
            Json(json!({
                "ok": false,
                "message": "Timeout waiting for bot stats response",
                "data": null
            }))
        }
    }
}

pub async fn handle_verify_bot_stats_response(request_id: String, data: Value) {
    let mut pending = PENDING_REQUESTS.lock().await;
    if let Some(sender) = pending.remove(&request_id) {
        let _ = sender.send(data);
    }
}
