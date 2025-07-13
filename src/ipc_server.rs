use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::{Any, CorsLayer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketMessage {
    pub event: String,
    pub data: serde_json::Value,
}

pub type ConnectedClients = Arc<RwLock<HashMap<String, broadcast::Sender<SocketMessage>>>>;

pub struct IpcServer {
    pub connected_clients: ConnectedClients,
}

impl IpcServer {
    pub fn new() -> Self {
        Self {
            connected_clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/ws/", get(websocket_handler))
            .layer(cors)
            .with_state(self.connected_clients.clone());

        let port = env::var("IPC_PORT")
            .unwrap_or_else(|_| "3001".to_string())
            .parse::<u16>()
            .unwrap_or(3001);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        println!("IPC Server listening on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(connected_clients): axum::extract::State<ConnectedClients>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, connected_clients))
}

async fn handle_socket(socket: WebSocket, connected_clients: ConnectedClients) {
    let client_id = uuid::Uuid::new_v4().to_string();

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = broadcast::channel::<SocketMessage>(100);

    {
        let mut clients = connected_clients.write().await;
        clients.insert(client_id.clone(), tx.clone());
    }

    let client_id_clone = client_id.clone();
    let client_id_clone2 = client_id.clone();
    let connected_clients_clone = connected_clients.clone();

    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let json_msg = match serde_json::to_string(&msg) {
                Ok(json) => json,
                Err(_) => continue,
            };

            if sender.send(Message::Text(json_msg)).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Ok(socket_msg) = serde_json::from_str::<SocketMessage>(&text) {
                        match socket_msg.event.as_str() {
                            "verifyBotStats" => {
                                if let Some(request_id) = socket_msg.data.get("request_id") {
                                    if let Some(request_id_str) = request_id.as_str() {
                                        crate::routes::bot::handle_verify_bot_stats_response(
                                            request_id_str.to_string(),
                                            socket_msg.data.clone(),
                                        )
                                        .await;
                                    }
                                }

                                let response_msg = SocketMessage {
                                    event: "verifyBotStatsResponse".to_string(),
                                    data: serde_json::json!({
                                        "status": "received",
                                        "timestamp": chrono::Utc::now().timestamp(),
                                        "client_id": client_id_clone
                                    }),
                                };

                                let _ = tx.send(response_msg);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    break;
                }
                Err(_) => {
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    {
        let mut clients = connected_clients_clone.write().await;
        clients.remove(&client_id_clone2);
    }
}

/* pub async fn send_to_client(
    connected_clients: &ConnectedClients,
    client_id: &str,
    message: SocketMessage,
) -> Result<(), String> {
    let clients = connected_clients.read().await;

    if let Some(sender) = clients.get(client_id) {
        sender
            .send(message)
            .map_err(|e| format!("Failed to send message: {}", e))?;
        Ok(())
    } else {
        Err(format!("Client {} not found", client_id))
    }
} */

pub async fn broadcast_to_all_clients(
    connected_clients: &ConnectedClients,
    message: SocketMessage,
) -> Vec<String> {
    let clients = connected_clients.read().await;
    let mut failed_clients = Vec::new();

    for (client_id, sender) in clients.iter() {
        if let Err(_) = sender.send(message.clone()) {
            failed_clients.push(client_id.clone());
        }
    }

    failed_clients
}

pub async fn get_connected_clients(connected_clients: &ConnectedClients) -> Vec<String> {
    let clients = connected_clients.read().await;
    clients.keys().cloned().collect()
}
