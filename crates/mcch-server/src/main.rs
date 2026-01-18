mod error;
mod handlers;
mod static_files;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, post, put};
use axum::Router;
use clap::Parser;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::handlers::*;
use crate::state::{create_default_config, load_config, AppState, KernelManager};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value = "system.toml")]
    config: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if !args.config.exists() {
        warn!("config file missing, creating default config");
        let _ = create_default_config(&args.config);
    }

    let (raw, config) = load_config(&args.config)?;
    let kernel_manager = KernelManager::from_config(&config)?;
    let state = Arc::new(AppState::new(args.config.clone(), raw, config, kernel_manager));

    let admin_routes = Router::new()
        .route("/providers", get(list_providers).post(create_provider))
        .route("/providers/:id", put(update_provider).delete(delete_provider))
        .route("/providers/test", post(provider_test))
        .route("/providers/simulate-selection", post(simulate_selection))
        .route("/templates/:kind", get(get_template))
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/:id", put(update_key).delete(delete_key))
        .route("/addresses", get(list_addresses).post(create_address))
        .route("/addresses/:id", put(update_address).delete(delete_address))
        .route("/links", get(list_links).post(create_link).delete(delete_link))
        .route("/policies", get(get_policies).put(update_policies))
        .route("/security/tokens", get(list_tokens).post(create_token))
        .route("/security/tokens/:id", put(update_token).delete(delete_token))
        .route("/system-config", get(get_system_config).put(update_system_config_handler))
        .route("/system/reload", post(reload_bundle))
        .route("/audit", get(list_audit))
        .route("/metrics", get(list_metrics))
        .route("/sessions/:id", get(get_session))
        .route("/context", get(get_context))
        .layer(middleware::from_fn_with_state(state.clone(), admin_auth));

    let app = Router::new()
        .route("/api/admin/login", post(login))
        .nest("/api", admin_routes)
        .route("/v1/messages", post(proxy_handler))
        .route("/v1/messages/count_tokens", post(proxy_handler))
        .route("/v1/chat/completions", post(proxy_handler))
        .route("/v1/responses", post(proxy_handler))
        .route("/v1/models", get(list_models))
        .fallback(static_files::static_handler)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("mcch-server listening on {}", args.listen);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

