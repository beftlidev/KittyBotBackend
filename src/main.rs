mod ipc_server;
mod routes;

use axum::{routing::get, Router};
use ipc_server::IpcServer;
use routes::bot;
use std::{net::SocketAddr, time::Duration};
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let serverport = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    let ipc_server = IpcServer::new();
    let connected_clients = ipc_server.connected_clients.clone();

    println!("Starting IPC Server...");

    tokio::spawn(async move {
        if let Err(e) = ipc_server.start().await {
            eprintln!("Failed to start IPC server: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("Starting REST API Server...");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        .route("/stats", get(bot::get_bot_stats))
        .with_state(connected_clients);

    let app = Router::new().nest("/api", api_routes).layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], serverport));
    println!(
        "REST API Server listening on http://localhost:{}",
        &serverport
    );
    println!("IPC WebSocket Server listening on ws://localhost:3001/ws/");
    println!("Press Ctrl+C to stop.");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
