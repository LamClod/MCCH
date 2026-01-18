use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Response};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use cookie::{Cookie, SameSite};
use kernel::{Forwarder, HttpRequest as KernelHttpRequest, Protocol, RequestEnvelope, ResponseBody};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::error::AppError;
use crate::state::{
    apply_policy_payload, build_policy_payload, update_config_file, AppState, PolicyPayload,
};

fn allow_all_descriptor() -> control_plane::SecurityDescriptor {
    control_plane::SecurityDescriptor {
        owner_sid: control_plane::Sid("owner".to_string()),
        group_sid: control_plane::Sid("group".to_string()),
        dacl: vec![control_plane::Ace {
            ace_type: control_plane::AceType::Allow,
            sid: control_plane::Sid("user".to_string()),
            access_mask: control_plane::AccessMask::all(),
            condition: None,
        }],
        sacl: Vec::new(),
        mandatory_label: control_plane::IntegrityLevel::Low,
    }
}

fn template_provider() -> control_plane::ProviderSpec {
    control_plane::ProviderSpec {
        id: "".to_string(),
        name: "".to_string(),
        provider_type: control_plane::ProviderType::Anthropic,
        priority: 0,
        weight: 1,
        enabled: true,
        group_tag: None,
        allowed_models: vec!["default".to_string()],
        model_redirects: HashMap::new(),
        join_claude_pool: false,
        limit_concurrent_sessions: 0,
        limit_rpm: 0,
        limit_concurrent: 0,
        context_1m_preference: control_plane::Context1mPreference::Inherit,
        security_descriptor: allow_all_descriptor(),
        base_url: "".to_string(),
        auth_header: None,
        auth_prefix: None,
        auth_query_param: None,
        default_headers: HashMap::new(),
    }
}

fn template_key() -> control_plane::KeySpec {
    control_plane::KeySpec {
        id: "".to_string(),
        provider_id: "".to_string(),
        name: "".to_string(),
        secret: "".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        allowed_models: Vec::new(),
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    }
}

fn template_address() -> control_plane::AddressSpec {
    control_plane::AddressSpec {
        id: "".to_string(),
        provider_id: "".to_string(),
        name: "".to_string(),
        base_url: "".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    }
}

fn template_link() -> control_plane::KeyAddressLink {
    control_plane::KeyAddressLink {
        provider_id: "".to_string(),
        key_id: "".to_string(),
        address_id: "".to_string(),
        priority: 0,
        weight: 1,
        enabled: true,
    }
}

fn template_token() -> control_plane::TokenRecord {
    control_plane::TokenRecord {
        token_key: "".to_string(),
        token: control_plane::SecurityToken {
            token_id: "".to_string(),
            user_sid: control_plane::Sid("user".to_string()),
            group_sids: Vec::new(),
            restricted_sids: Vec::new(),
            privileges: Vec::new(),
            integrity_level: control_plane::IntegrityLevel::Medium,
            claims: HashMap::new(),
            flags: control_plane::TokenFlags::empty(),
        },
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct SimpleResponse {
    pub ok: bool,
}

#[derive(Serialize)]
pub struct SystemConfigResponse {
    pub content: String,
    pub keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct SystemConfigUpdate {
    pub content: String,
}

#[derive(Deserialize)]
pub struct SelectionRequest {
    pub model: String,
    pub protocol: String,
    pub group: Option<String>,
    pub requires_context_1m: Option<bool>,
    pub token_key: Option<String>,
}

#[derive(Serialize)]
pub struct SelectionResponse {
    pub provider_id: String,
    pub key_id: String,
    pub address_id: String,
    pub resolved_model: String,
}

#[derive(Deserialize)]
pub struct ProviderTestRequest {
    pub provider_id: String,
    pub key_id: String,
    pub address_id: String,
    pub model: String,
    pub protocol: String,
    pub stream: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Serialize)]
pub struct ProviderTestResponse {
    pub url: String,
    pub status: Option<u16>,
    pub body: Option<String>,
}

#[derive(Deserialize)]
pub struct LinkKey {
    pub provider_id: String,
    pub key_id: String,
    pub address_id: String,
}

#[derive(Deserialize)]
pub struct SessionQuery {
    pub session_id: Option<String>,
}

#[derive(Serialize)]
pub struct ModelsResponse {
    pub object: String,
    pub data: Vec<ModelItem>,
}

#[derive(Serialize)]
pub struct ModelItem {
    pub id: String,
}

#[derive(Serialize)]
pub struct MetricPointResponse {
    pub name: String,
    pub value: f64,
    pub timestamp_ms: u64,
    pub tags: HashMap<String, String>,
}

pub async fn admin_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response<Body>, AppError> {
    let token = extract_bearer_token(req.headers()).or_else(|| extract_cookie_token(req.headers()));
    let expected = state.admin_token.read().await.clone();

    if expected.trim().is_empty() || token.as_deref() != Some(expected.as_str()) {
        return Err(AppError::unauthorized("invalid admin token"));
    }

    Ok(next.run(req).await)
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Response<Body>, AppError> {
    let expected = state.admin_token.read().await.clone();
    if expected.trim().is_empty() {
        return Err(AppError::unauthorized("admin token not configured"));
    }
    if payload.token != expected {
        return Err(AppError::unauthorized("invalid admin token"));
    }

    let cookie = Cookie::build(("mcch_admin", payload.token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    let mut response = Json(SimpleResponse { ok: true }).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap());
    Ok(response)
}

pub async fn get_system_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SystemConfigResponse>, AppError> {
    let content = state.config_raw.read().await.clone();
    let keys = state.config.read().await.keys();
    Ok(Json(SystemConfigResponse { content, keys }))
}

pub async fn update_system_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SystemConfigUpdate>,
) -> Result<Json<SimpleResponse>, AppError> {
    let config = update_config_file(&state, payload.content).await?;
    let snapshot = load_snapshot(state.clone()).await?;
    state.kernel_manager.reload(&snapshot).await;
    let new_token = config.get_string("security.kernel_token");
    *state.admin_token.write().await = new_token;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn reload_bundle(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SimpleResponse>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    state.kernel_manager.reload(&snapshot).await;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_models(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ModelsResponse>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    let mut models: HashSet<String> = HashSet::new();

    for provider in &snapshot.providers.providers {
        if provider.allowed_models.is_empty() {
            continue;
        }
        for model in &provider.allowed_models {
            models.insert(model.clone());
        }
        for (from, to) in &provider.model_redirects {
            models.insert(from.clone());
            models.insert(to.clone());
        }
    }

    if models.is_empty() {
        models.insert("default".to_string());
    }

    let data = models
        .into_iter()
        .map(|id| ModelItem { id })
        .collect();

    Ok(Json(ModelsResponse {
        object: "list".to_string(),
        data,
    }))
}

pub async fn get_template(Path(kind): Path<String>) -> Result<Json<Value>, AppError> {
    let value = match kind.as_str() {
        "provider" => serde_json::to_value(template_provider())
            .map_err(|err| AppError::internal(err.to_string()))?,
        "key" => serde_json::to_value(template_key())
            .map_err(|err| AppError::internal(err.to_string()))?,
        "address" => serde_json::to_value(template_address())
            .map_err(|err| AppError::internal(err.to_string()))?,
        "link" => serde_json::to_value(template_link())
            .map_err(|err| AppError::internal(err.to_string()))?,
        "token" => serde_json::to_value(template_token())
            .map_err(|err| AppError::internal(err.to_string()))?,
        _ => return Err(AppError::not_found("template not found")),
    };
    Ok(Json(value))
}

pub async fn list_providers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::ProviderSpec>>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(snapshot.providers.providers))
}

pub async fn create_provider(
    State(state): State<Arc<AppState>>,
    Json(mut provider): Json<control_plane::ProviderSpec>,
) -> Result<Json<control_plane::ProviderSpec>, AppError> {
    if provider.id.trim().is_empty() {
        provider.id = Uuid::new_v4().to_string();
    }
    update_snapshot(state.clone(), |snapshot| {
        snapshot.providers.providers.push(provider.clone());
        rebuild_provider_snapshot(snapshot);
        Ok(provider)
    })
    .await
    .map(Json)
}

pub async fn update_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
    Json(mut provider): Json<control_plane::ProviderSpec>,
) -> Result<Json<control_plane::ProviderSpec>, AppError> {
    if provider.id.trim().is_empty() {
        provider.id = provider_id.clone();
    }
    if provider.id != provider_id {
        return Err(AppError::bad_request("provider id mismatch"));
    }

    update_snapshot(state.clone(), move |snapshot| {
        let item = snapshot
            .providers
            .providers
            .iter_mut()
            .find(|item| item.id == provider_id)
            .ok_or_else(|| AppError::not_found("provider not found"))?;
        *item = provider.clone();
        rebuild_provider_snapshot(snapshot);
        Ok(provider)
    })
    .await
    .map(Json)
}

pub async fn delete_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        snapshot
            .providers
            .providers
            .retain(|item| item.id != provider_id);
        snapshot
            .providers
            .keys
            .retain(|item| item.provider_id != provider_id);
        snapshot
            .providers
            .addresses
            .retain(|item| item.provider_id != provider_id);
        snapshot
            .providers
            .links
            .retain(|item| item.provider_id != provider_id);
        rebuild_provider_snapshot(snapshot);
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::KeySpec>>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(snapshot.providers.keys))
}

pub async fn create_key(
    State(state): State<Arc<AppState>>,
    Json(mut key): Json<control_plane::KeySpec>,
) -> Result<Json<control_plane::KeySpec>, AppError> {
    if key.id.trim().is_empty() {
        key.id = Uuid::new_v4().to_string();
    }
    update_snapshot(state.clone(), |snapshot| {
        snapshot.providers.keys.push(key.clone());
        rebuild_provider_snapshot(snapshot);
        Ok(key)
    })
    .await
    .map(Json)
}

pub async fn update_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
    Json(mut key): Json<control_plane::KeySpec>,
) -> Result<Json<control_plane::KeySpec>, AppError> {
    if key.id.trim().is_empty() {
        key.id = key_id.clone();
    }
    if key.id != key_id {
        return Err(AppError::bad_request("key id mismatch"));
    }
    update_snapshot(state.clone(), move |snapshot| {
        let item = snapshot
            .providers
            .keys
            .iter_mut()
            .find(|item| item.id == key_id)
            .ok_or_else(|| AppError::not_found("key not found"))?;
        *item = key.clone();
        rebuild_provider_snapshot(snapshot);
        Ok(key)
    })
    .await
    .map(Json)
}

pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        snapshot.providers.keys.retain(|item| item.id != key_id);
        snapshot
            .providers
            .links
            .retain(|item| item.key_id != key_id);
        rebuild_provider_snapshot(snapshot);
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_addresses(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::AddressSpec>>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(snapshot.providers.addresses))
}

pub async fn create_address(
    State(state): State<Arc<AppState>>,
    Json(mut address): Json<control_plane::AddressSpec>,
) -> Result<Json<control_plane::AddressSpec>, AppError> {
    if address.id.trim().is_empty() {
        address.id = Uuid::new_v4().to_string();
    }
    update_snapshot(state.clone(), |snapshot| {
        snapshot.providers.addresses.push(address.clone());
        rebuild_provider_snapshot(snapshot);
        Ok(address)
    })
    .await
    .map(Json)
}

pub async fn update_address(
    State(state): State<Arc<AppState>>,
    Path(address_id): Path<String>,
    Json(mut address): Json<control_plane::AddressSpec>,
) -> Result<Json<control_plane::AddressSpec>, AppError> {
    if address.id.trim().is_empty() {
        address.id = address_id.clone();
    }
    if address.id != address_id {
        return Err(AppError::bad_request("address id mismatch"));
    }
    update_snapshot(state.clone(), move |snapshot| {
        let item = snapshot
            .providers
            .addresses
            .iter_mut()
            .find(|item| item.id == address_id)
            .ok_or_else(|| AppError::not_found("address not found"))?;
        *item = address.clone();
        rebuild_provider_snapshot(snapshot);
        Ok(address)
    })
    .await
    .map(Json)
}

pub async fn delete_address(
    State(state): State<Arc<AppState>>,
    Path(address_id): Path<String>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        snapshot
            .providers
            .addresses
            .retain(|item| item.id != address_id);
        snapshot
            .providers
            .links
            .retain(|item| item.address_id != address_id);
        rebuild_provider_snapshot(snapshot);
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_links(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::KeyAddressLink>>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(snapshot.providers.links))
}

pub async fn create_link(
    State(state): State<Arc<AppState>>,
    Json(link): Json<control_plane::KeyAddressLink>,
) -> Result<Json<control_plane::KeyAddressLink>, AppError> {
    update_snapshot(state.clone(), |snapshot| {
        snapshot.providers.links.push(link.clone());
        rebuild_provider_snapshot(snapshot);
        Ok(link)
    })
    .await
    .map(Json)
}

pub async fn delete_link(
    State(state): State<Arc<AppState>>,
    Json(link): Json<LinkKey>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        snapshot.providers.links.retain(|item| {
            !(item.provider_id == link.provider_id
                && item.key_id == link.key_id
                && item.address_id == link.address_id)
        });
        rebuild_provider_snapshot(snapshot);
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn get_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PolicyPayload>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(build_policy_payload(&snapshot)))
}

pub async fn update_policies(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PolicyPayload>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        apply_policy_payload(snapshot, payload.clone());
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::TokenRecord>>, AppError> {
    let snapshot = load_snapshot(state.clone()).await?;
    Ok(Json(snapshot.tokens))
}

pub async fn create_token(
    State(state): State<Arc<AppState>>,
    Json(mut token): Json<control_plane::TokenRecord>,
) -> Result<Json<control_plane::TokenRecord>, AppError> {
    if token.token_key.trim().is_empty() {
        token.token_key = Uuid::new_v4().to_string();
    }
    update_snapshot(state.clone(), |snapshot| {
        snapshot.tokens.push(token.clone());
        Ok(token)
    })
    .await
    .map(Json)
}

pub async fn update_token(
    State(state): State<Arc<AppState>>,
    Path(token_key): Path<String>,
    Json(mut token): Json<control_plane::TokenRecord>,
) -> Result<Json<control_plane::TokenRecord>, AppError> {
    if token.token_key.trim().is_empty() {
        token.token_key = token_key.clone();
    }
    if token.token_key != token_key {
        return Err(AppError::bad_request("token key mismatch"));
    }
    update_snapshot(state.clone(), move |snapshot| {
        let item = snapshot
            .tokens
            .iter_mut()
            .find(|item| item.token_key == token_key)
            .ok_or_else(|| AppError::not_found("token not found"))?;
        *item = token.clone();
        Ok(token)
    })
    .await
    .map(Json)
}

pub async fn delete_token(
    State(state): State<Arc<AppState>>,
    Path(token_key): Path<String>,
) -> Result<Json<SimpleResponse>, AppError> {
    update_snapshot(state.clone(), move |snapshot| {
        snapshot.tokens.retain(|item| item.token_key != token_key);
        Ok(())
    })
    .await?;
    Ok(Json(SimpleResponse { ok: true }))
}

pub async fn list_audit(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<control_plane::AuditEvent>>, AppError> {
    let bundle = state.kernel_manager.bundle.read().await;
    Ok(Json(bundle.audit.list()))
}

pub async fn list_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<MetricPointResponse>>, AppError> {
    let bundle = state.kernel_manager.bundle.read().await;
    let points = bundle
        .metrics
        .list()
        .into_iter()
        .map(|point| MetricPointResponse {
            name: point.name,
            value: point.value,
            timestamp_ms: point.timestamp_ms,
            tags: point.tags,
        })
        .collect();
    Ok(Json(points))
}

pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<HashMap<String, String>>, AppError> {
    let bundle = state.kernel_manager.bundle.read().await;
    let binding = bundle.sessions.get_binding(&session_id);
    let mut payload = HashMap::new();
    if let Some(provider_id) = binding {
        payload.insert("provider_id".to_string(), provider_id);
    }
    Ok(Json(payload))
}

pub async fn get_context(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<Vec<control_plane::ContextMessage>>, AppError> {
    let Some(session_id) = query.session_id else {
        return Err(AppError::bad_request("session_id required"));
    };
    let bundle = state.kernel_manager.bundle.read().await;
    Ok(Json(bundle.context_store.load(&session_id)))
}

pub async fn simulate_selection(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SelectionRequest>,
) -> Result<Json<SelectionResponse>, AppError> {
    let protocol = parse_protocol(&payload.protocol)?;
    let bundle = state.kernel_manager.bundle.read().await;
    let snapshot = bundle.providers.snapshot();

    let token = payload
        .token_key
        .as_deref()
        .and_then(|token_key| bundle.security.authenticate(Some(token_key)));

    let criteria = kernel::SelectionCriteria {
        model: payload.model,
        protocol,
        group: payload.group,
        requires_context_1m: payload.requires_context_1m.unwrap_or(false),
    };

    let selector = kernel::SelectionEngine::new(
        state.kernel_manager.access.clone(),
        bundle.health.clone(),
        bundle.rate_limiter.clone(),
    );

    let decision = selector
        .select(&snapshot, &criteria, &kernel::SelectionExclusions::default(), token.as_ref())
        .map_err(|err| AppError::bad_request(err.to_string()))?;

    Ok(Json(SelectionResponse {
        provider_id: decision.provider.id,
        key_id: decision.key.id,
        address_id: decision.address.id,
        resolved_model: decision.resolved_model,
    }))
}

pub async fn provider_test(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProviderTestRequest>,
) -> Result<Json<ProviderTestResponse>, AppError> {
    let protocol = parse_protocol(&payload.protocol)?;
    let stream = payload.stream.unwrap_or(false);

    let snapshot = load_snapshot(state.clone()).await?;
    let provider = snapshot
        .providers
        .providers
        .iter()
        .find(|item| item.id == payload.provider_id)
        .ok_or_else(|| AppError::not_found("provider not found"))?
        .clone();
    let key = snapshot
        .providers
        .keys
        .iter()
        .find(|item| item.id == payload.key_id)
        .ok_or_else(|| AppError::not_found("key not found"))?
        .clone();
    let address = snapshot
        .providers
        .addresses
        .iter()
        .find(|item| item.id == payload.address_id)
        .ok_or_else(|| AppError::not_found("address not found"))?
        .clone();

    let raw_body = serde_json::to_vec(&build_provider_test_body(protocol, &payload.model, stream))
        .unwrap_or_else(|_| b"{}".to_vec());

    let request = RequestEnvelope {
        request_id: Uuid::new_v4().to_string(),
        protocol,
        model: payload.model,
        stream,
        session_id: None,
        token_key: None,
        client_id: None,
        client_version: None,
        is_probe: false,
        is_warmup: false,
        requires_context_1m: false,
        headers: HashMap::new(),
        raw_body,
        kernel_request: None,
        extra: HashMap::from([("path".to_string(), "/v1/messages".to_string())]),
    };

    let plugin = state
        .kernel_manager
        .kernel_space
        .providers
        .iter()
        .find(|plugin| plugin.provider_type() == provider.provider_type)
        .ok_or_else(|| AppError::bad_request("provider plugin not found"))?
        .clone();

    let upstream = plugin
        .build_upstream(&request, &provider, &key, &address)
        .map_err(|err| AppError::bad_request(err.to_string()))?;

    if payload.dry_run.unwrap_or(false) {
        return Ok(Json(ProviderTestResponse {
            url: upstream.url,
            status: None,
            body: None,
        }));
    }

    let forwarder = kernel::HttpForwarder::new(kernel::HttpForwarderConfig::default());
    let response = forwarder
        .send(&upstream)
        .await
        .map_err(|err| AppError::bad_request(err.to_string()))?;
    let body = response.body.into_bytes_async().await;
    let body_text = String::from_utf8_lossy(&body).chars().take(2048).collect();

    Ok(Json(ProviderTestResponse {
        url: upstream.url,
        status: Some(response.status),
        body: Some(body_text),
    }))
}

fn build_provider_test_body(protocol: Protocol, model: &str, stream: bool) -> Value {
    match protocol {
        Protocol::Anthropic => json!({
            "model": model,
            "max_tokens": 16,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "ping"
                        }
                    ]
                }
            ],
            "stream": stream
        }),
        Protocol::Codex => json!({
            "model": model,
            "input": "ping",
            "stream": stream
        }),
        Protocol::Gemini => json!({
            "model": model,
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": "ping"
                        }
                    ]
                }
            ]
        }),
        Protocol::OpenAi => json!({
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": "ping"
                }
            ],
            "stream": stream
        }),
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response<Body>, AppError> {
    let (parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let path = parts.uri.path().to_string();
    let headers = convert_headers(&parts.headers);
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    let kernel_req = KernelHttpRequest {
        method,
        path,
        headers,
        body: body_bytes.to_vec(),
    };

    let kernel = state.kernel_manager.kernel.read().await.clone();
    let response = kernel.handle_http(kernel_req).await?;

    kernel_response_to_http(response).await
}

fn convert_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            map.insert(name.as_str().to_lowercase(), value.to_string());
        }
    }
    map
}

async fn kernel_response_to_http(response: kernel::HttpResponse) -> Result<Response<Body>, AppError> {
    let mut builder = Response::builder().status(response.status);
    for (key, value) in response.headers {
        if let (Ok(name), Ok(value)) = (
            key.parse::<header::HeaderName>(),
            HeaderValue::from_str(&value),
        ) {
            builder = builder.header(name, value);
        }
    }

    let body = match response.body {
        ResponseBody::Bytes(bytes) => Body::from(bytes),
        ResponseBody::Reader(reader) => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
            tokio::task::spawn_blocking(move || {
                let mut reader = reader;
                let mut buffer = vec![0u8; 8192];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.blocking_send(Ok(Bytes::copy_from_slice(&buffer[..n]))).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = tx.blocking_send(Err(err));
                            break;
                        }
                    }
                }
            });
            let stream = ReceiverStream::new(rx);
            Body::from_stream(stream)
        }
        ResponseBody::Stream(stream) => Body::from_stream(stream),
    };

    builder
        .body(body)
        .map_err(|err| AppError::internal(err.to_string()))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn extract_cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Ok(cookie) = Cookie::parse(trimmed.to_string()) {
            if cookie.name() == "mcch_admin" {
                return Some(cookie.value().to_string());
            }
        }
    }
    None
}

fn rebuild_provider_snapshot(snapshot: &mut control_plane::BusinessSnapshot) {
    let providers = snapshot.providers.providers.clone();
    let keys = snapshot.providers.keys.clone();
    let addresses = snapshot.providers.addresses.clone();
    let links = snapshot.providers.links.clone();
    snapshot.providers = control_plane::ProviderSnapshot::new(providers, keys, addresses, links);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use crate::state::{KernelManager, StoreHandles};
    use control_plane::{
        AccessCheckConfig, AccessChecker, AccessMask, Ace, AceType, AddressSpec, BusinessSnapshot,
        CircuitBreakerConfig, Context1mPreference, InMemoryAuditSink, InMemoryBusinessRepository,
        InMemoryContextStore, InMemoryHealthStore, InMemoryRateLimiter, InMemorySessionStore,
        InMemoryTsdbSink, KeyAddressLink, KeySpec, ProviderSnapshot, ProviderSpec, ProviderType,
        SecurityDescriptor, SecurityToken, Sid, SystemConfig, SystemConfigLoader, TokenFlags,
        TokenRecord,
    };
    use kernel::{
        InMemoryForwarder, Kernel, KernelConfig, Protocol, SelectionCriteria, SelectionEngine,
        SelectionExclusions,
    };
    use kernel_space::{BasicProtocol, EchoProvider, KernelSpaceBundle};
    use tokio::sync::RwLock;
    use uuid::Uuid;

    fn allow_all_descriptor() -> SecurityDescriptor {
        SecurityDescriptor {
            owner_sid: Sid("owner".to_string()),
            group_sid: Sid("group".to_string()),
            dacl: vec![Ace {
                ace_type: AceType::Allow,
                sid: Sid("user".to_string()),
                access_mask: AccessMask::all(),
                condition: None,
            }],
            sacl: Vec::new(),
            mandatory_label: control_plane::IntegrityLevel::Low,
        }
    }

    fn base_token(token_id: &str) -> SecurityToken {
        SecurityToken {
            token_id: token_id.to_string(),
            user_sid: Sid("user".to_string()),
            group_sids: Vec::new(),
            restricted_sids: Vec::new(),
            privileges: Vec::new(),
            integrity_level: control_plane::IntegrityLevel::Medium,
            claims: HashMap::new(),
            flags: TokenFlags::empty(),
        }
    }

    fn sample_snapshot(with_token: bool) -> BusinessSnapshot {
        let descriptor = allow_all_descriptor();
        let provider = ProviderSpec {
            id: "p1".to_string(),
            name: "provider-1".to_string(),
            provider_type: ProviderType::Anthropic,
            priority: 0,
            weight: 1,
            enabled: true,
            group_tag: None,
            allowed_models: vec!["default".to_string()],
            model_redirects: HashMap::new(),
            join_claude_pool: true,
            limit_concurrent_sessions: 0,
            limit_rpm: 0,
            limit_concurrent: 0,
            context_1m_preference: Context1mPreference::Inherit,
            security_descriptor: descriptor.clone(),
            base_url: "http://example".to_string(),
            auth_header: None,
            auth_prefix: None,
            auth_query_param: None,
            default_headers: HashMap::new(),
        };
        let key = KeySpec {
            id: "k1".to_string(),
            provider_id: "p1".to_string(),
            name: "key-1".to_string(),
            secret: "secret".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            allowed_models: Vec::new(),
            limit_rpm: 0,
            limit_concurrent: 0,
            security_descriptor: descriptor.clone(),
        };
        let address = AddressSpec {
            id: "a1".to_string(),
            provider_id: "p1".to_string(),
            name: "addr-1".to_string(),
            base_url: "http://example".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            limit_rpm: 0,
            limit_concurrent: 0,
            security_descriptor: descriptor.clone(),
        };
        let link = KeyAddressLink {
            provider_id: "p1".to_string(),
            key_id: "k1".to_string(),
            address_id: "a1".to_string(),
            priority: 0,
            weight: 1,
            enabled: true,
        };
        let providers = ProviderSnapshot::new(vec![provider], vec![key], vec![address], vec![link]);
        let mut snapshot = BusinessSnapshot::default();
        snapshot.providers = providers;
        if with_token {
            snapshot.tokens.push(TokenRecord {
                token_key: "token-1".to_string(),
                token: base_token("token-1"),
            });
        }
        snapshot
    }

    fn snapshot_with_limits(limit_rpm: u32) -> BusinessSnapshot {
        let descriptor = allow_all_descriptor();
        let provider = ProviderSpec {
            id: "p1".to_string(),
            name: "provider-1".to_string(),
            provider_type: ProviderType::Anthropic,
            priority: 0,
            weight: 1,
            enabled: true,
            group_tag: None,
            allowed_models: vec!["default".to_string()],
            model_redirects: HashMap::new(),
            join_claude_pool: true,
            limit_concurrent_sessions: 0,
            limit_rpm,
            limit_concurrent: 0,
            context_1m_preference: Context1mPreference::Inherit,
            security_descriptor: descriptor.clone(),
            base_url: "http://example".to_string(),
            auth_header: None,
            auth_prefix: None,
            auth_query_param: None,
            default_headers: HashMap::new(),
        };
        let key = KeySpec {
            id: "k1".to_string(),
            provider_id: "p1".to_string(),
            name: "key-1".to_string(),
            secret: "secret".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            allowed_models: Vec::new(),
            limit_rpm,
            limit_concurrent: 0,
            security_descriptor: descriptor.clone(),
        };
        let address = AddressSpec {
            id: "a1".to_string(),
            provider_id: "p1".to_string(),
            name: "addr-1".to_string(),
            base_url: "http://example".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            limit_rpm,
            limit_concurrent: 0,
            security_descriptor: descriptor,
        };
        let link = KeyAddressLink {
            provider_id: "p1".to_string(),
            key_id: "k1".to_string(),
            address_id: "a1".to_string(),
            priority: 0,
            weight: 1,
            enabled: true,
        };
        let providers = ProviderSnapshot::new(vec![provider], vec![key], vec![address], vec![link]);
        let mut snapshot = BusinessSnapshot::default();
        snapshot.providers = providers;
        snapshot
    }

    fn test_config(token: &str) -> (String, SystemConfig) {
        let raw = format!(
            "storage = {{ dsn = \"\", sqlite_path = \":memory:\" }}\ncache = {{ redis_url = \"\" }}\ntsdb = {{ endpoint = \"\", sqlite_path = \":memory:\", timeout_ms = 1000 }}\nsecurity = {{ kernel_token = \"{token}\", master_key = \"\" }}\nruntime = {{ thread_pool = 2, cache_ttl_seconds = 30 }}\nbootstrap = {{ seed_on_start = false }}\n"
        );
        let config = SystemConfigLoader::from_str(&raw).expect("config parse");
        (raw, config)
    }

    fn temp_config_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("mcch-test-{}.toml", Uuid::new_v4()));
        path
    }

    fn build_state(snapshot: BusinessSnapshot, config_path: PathBuf, token: &str) -> Arc<AppState> {
        let stores = StoreHandles {
            sessions: InMemorySessionStore::shared(),
            rate_limiter: InMemoryRateLimiter::shared(60),
            health: InMemoryHealthStore::shared(CircuitBreakerConfig::default()),
            audit: InMemoryAuditSink::shared(),
            context_store: InMemoryContextStore::shared(),
            metrics: InMemoryTsdbSink::shared(),
        };
        let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
        let forwarder = Arc::new(InMemoryForwarder);
        let kernel_space = KernelSpaceBundle {
            protocols: vec![Arc::new(BasicProtocol)],
            providers: vec![Arc::new(EchoProvider)],
            guard_plugins: Vec::new(),
        };
        let bundle = control_plane::bootstrap::from_snapshot_with_stores(
            &snapshot,
            stores.to_control_plane_stores(),
        );
        let mut kernel = Kernel::new(
            KernelConfig::default(),
            bundle.security.clone(),
            access.clone(),
            bundle.policy.clone(),
            bundle.providers.clone(),
            bundle.sessions.clone(),
            bundle.rate_limiter.clone(),
            bundle.health.clone(),
            bundle.audit.clone(),
            bundle.metrics.clone(),
            bundle.context_store.clone(),
            forwarder.clone(),
        );
        for plugin in &kernel_space.protocols {
            kernel.register_protocol_plugin(plugin.clone());
        }
        for plugin in &kernel_space.providers {
            kernel.register_provider_plugin(plugin.clone());
        }
        for plugin in &kernel_space.guard_plugins {
            kernel.register_guard_plugin(plugin.clone());
        }

        let repo: Arc<dyn control_plane::BusinessRepository> =
            Arc::new(InMemoryBusinessRepository::new(snapshot));
        let manager = KernelManager {
            repo,
            stores,
            access,
            forwarder,
            kernel_space,
            bundle: RwLock::new(bundle),
            kernel: RwLock::new(Arc::new(kernel)),
        };
        let (raw, config) = test_config(token);
        Arc::new(AppState::new(config_path, raw, config, manager))
    }

    #[tokio::test]
    async fn admin_crud_roundtrip() {
        let state = build_state(BusinessSnapshot::default(), temp_config_path(), "admin-token");
        let descriptor = allow_all_descriptor();
        let provider = ProviderSpec {
            id: "p1".to_string(),
            name: "provider-1".to_string(),
            provider_type: ProviderType::Anthropic,
            priority: 0,
            weight: 1,
            enabled: true,
            group_tag: None,
            allowed_models: vec!["default".to_string()],
            model_redirects: HashMap::new(),
            join_claude_pool: true,
            limit_concurrent_sessions: 0,
            limit_rpm: 0,
            limit_concurrent: 0,
            context_1m_preference: Context1mPreference::Inherit,
            security_descriptor: descriptor.clone(),
            base_url: "http://example".to_string(),
            auth_header: None,
            auth_prefix: None,
            auth_query_param: None,
            default_headers: HashMap::new(),
        };
        let Json(created_provider) =
            create_provider(State(state.clone()), Json(provider.clone()))
                .await
                .expect("create provider");
        assert_eq!(created_provider.id, provider.id);

        let key = KeySpec {
            id: "k1".to_string(),
            provider_id: provider.id.clone(),
            name: "key-1".to_string(),
            secret: "secret".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            allowed_models: Vec::new(),
            limit_rpm: 0,
            limit_concurrent: 0,
            security_descriptor: descriptor.clone(),
        };
        let Json(created_key) = create_key(State(state.clone()), Json(key.clone()))
            .await
            .expect("create key");
        assert_eq!(created_key.id, key.id);

        let address = AddressSpec {
            id: "a1".to_string(),
            provider_id: provider.id.clone(),
            name: "addr-1".to_string(),
            base_url: "http://example".to_string(),
            enabled: true,
            priority: 0,
            weight: 1,
            limit_rpm: 0,
            limit_concurrent: 0,
            security_descriptor: descriptor.clone(),
        };
        let Json(created_address) = create_address(State(state.clone()), Json(address.clone()))
            .await
            .expect("create address");
        assert_eq!(created_address.id, address.id);

        let link = KeyAddressLink {
            provider_id: provider.id.clone(),
            key_id: key.id.clone(),
            address_id: address.id.clone(),
            priority: 0,
            weight: 1,
            enabled: true,
        };
        let Json(created_link) = create_link(State(state.clone()), Json(link.clone()))
            .await
            .expect("create link");
        assert_eq!(created_link.provider_id, link.provider_id);

        let Json(links) = list_links(State(state.clone())).await.expect("list links");
        assert_eq!(links.len(), 1);

        let mut updated_provider = provider.clone();
        updated_provider.name = "provider-2".to_string();
        let Json(updated) = update_provider(
            State(state.clone()),
            Path(provider.id.clone()),
            Json(updated_provider),
        )
        .await
        .expect("update provider");
        assert_eq!(updated.name, "provider-2");

        let _ = delete_provider(State(state.clone()), Path(provider.id.clone()))
            .await
            .expect("delete provider");

        let Json(providers) = list_providers(State(state.clone()))
            .await
            .expect("list providers");
        assert!(providers.is_empty());
        let Json(keys) = list_keys(State(state.clone()))
            .await
            .expect("list keys");
        assert!(keys.is_empty());
        let Json(addresses) = list_addresses(State(state.clone()))
            .await
            .expect("list addresses");
        assert!(addresses.is_empty());
        let Json(links) = list_links(State(state.clone()))
            .await
            .expect("list links");
        assert!(links.is_empty());
    }

    #[tokio::test]
    async fn proxy_flow_echoes_body() {
        let state = build_state(sample_snapshot(false), temp_config_path(), "admin-token");
        let payload = br#"{"hello":"world"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("content-type", "application/json")
            .body(Body::from(payload.as_ref()))
            .expect("request build");
        let response = proxy_handler(State(state), request)
            .await
            .expect("proxy handler");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert_eq!(body.as_ref(), payload.as_ref());
    }

    #[tokio::test]
    async fn selection_simulator_returns_decision() {
        let state = build_state(sample_snapshot(true), temp_config_path(), "admin-token");
        let payload = SelectionRequest {
            model: "default".to_string(),
            protocol: "anthropic".to_string(),
            group: None,
            requires_context_1m: None,
            token_key: Some("token-1".to_string()),
        };
        let Json(result) = simulate_selection(State(state), Json(payload))
            .await
            .expect("simulate selection");
        assert_eq!(result.provider_id, "p1");
        assert_eq!(result.key_id, "k1");
        assert_eq!(result.address_id, "a1");
        assert_eq!(result.resolved_model, "default");
    }

    #[tokio::test]
    async fn system_config_update_updates_admin_token() {
        let path = temp_config_path();
        let state = build_state(sample_snapshot(false), path.clone(), "old-token");
        let (content, _) = test_config("new-token");
        let Json(result) = update_system_config_handler(
            State(state.clone()),
            Json(SystemConfigUpdate { content: content.clone() }),
        )
        .await
        .expect("update system config");
        assert!(result.ok);
        let updated = state.admin_token.read().await.clone();
        assert_eq!(updated, "new-token");
        let file_content = std::fs::read_to_string(&path).expect("read config file");
        assert_eq!(file_content, content);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn selection_respects_rate_limit() {
        let snapshot = snapshot_with_limits(1);
        let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
        let health = InMemoryHealthStore::shared(CircuitBreakerConfig::default());
        let rate_limiter = InMemoryRateLimiter::shared(60);
        let engine = SelectionEngine::new(access, health, rate_limiter);
        let criteria = SelectionCriteria {
            model: "default".to_string(),
            protocol: Protocol::Anthropic,
            group: None,
            requires_context_1m: false,
        };
        let first = engine.select(
            &snapshot.providers,
            &criteria,
            &SelectionExclusions::default(),
            None,
        );
        assert!(first.is_ok());
        drop(first);
        let second = engine.select(
            &snapshot.providers,
            &criteria,
            &SelectionExclusions::default(),
            None,
        );
        assert!(second.is_err());
    }

    #[test]
    fn selection_skips_unhealthy_provider() {
        let snapshot = sample_snapshot(false);
        let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
        let health = InMemoryHealthStore::new(CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            open_duration_ms: 60_000,
            half_open_success_threshold: 1,
        });
        control_plane::HealthStore::record_failure(&health, "p1");
        let engine = SelectionEngine::new(
            access,
            Arc::new(health),
            InMemoryRateLimiter::shared(60),
        );
        let criteria = SelectionCriteria {
            model: "default".to_string(),
            protocol: Protocol::Anthropic,
            group: None,
            requires_context_1m: false,
        };
        let result = engine.select(
            &snapshot.providers,
            &criteria,
            &SelectionExclusions::default(),
            None,
        );
        assert!(result.is_err());
    }
}

async fn load_snapshot(state: Arc<AppState>) -> Result<control_plane::BusinessSnapshot, AppError> {
    let repo = state.kernel_manager.repo.clone();
    tokio::task::spawn_blocking(move || repo.load_snapshot().map_err(AppError::from))
        .await
        .map_err(|err| AppError::internal(err.to_string()))?
}

async fn update_snapshot<F, R>(
    state: Arc<AppState>,
    mutator: F,
) -> Result<R, AppError>
where
    F: FnOnce(&mut control_plane::BusinessSnapshot) -> Result<R, AppError> + Send + 'static,
    R: Send + 'static,
{
    let _guard = state.snapshot_lock.lock().await;
    let repo = state.kernel_manager.repo.clone();
    tokio::task::spawn_blocking(move || {
        let mut snapshot = repo.load_snapshot().map_err(AppError::from)?;
        let result = mutator(&mut snapshot)?;
        repo.save_snapshot(&snapshot).map_err(AppError::from)?;
        Ok(result)
    })
    .await
    .map_err(|err| AppError::internal(err.to_string()))?
}

fn parse_protocol(input: &str) -> Result<Protocol, AppError> {
    match input.to_lowercase().as_str() {
        "openai" | "openai-compatible" => Ok(Protocol::OpenAi),
        "anthropic" | "claude" => Ok(Protocol::Anthropic),
        "codex" | "response" => Ok(Protocol::Codex),
        "gemini" => Ok(Protocol::Gemini),
        _ => Err(AppError::bad_request("invalid protocol")),
    }
}

