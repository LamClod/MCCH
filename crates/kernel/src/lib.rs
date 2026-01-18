mod guard;
mod selector;
mod types;
mod forwarder;

pub use guard::{build_kernel_request, classify_request, GuardPipeline, GuardStepKey, RequestType};
pub use selector::{
    SelectionCriteria, SelectionDecision, SelectionEngine, SelectionExclusions, SelectorError,
};
pub use forwarder::{HttpForwarder, HttpForwarderConfig};
pub use types::{
    ContentBlock, HttpRequest, HttpResponse, KernelRequest, KernelResponse, Message, Protocol,
    RequestEnvelope, ResponseBody, ToolSpec, UpstreamRequest, UpstreamResponse,
};

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use control_plane::{
    AccessCheckEngine, AuditEvent, AuditSink, ContextMessage, ContextStore, FilterAction,
    GuardConfig, HealthStore, MetricPoint, PolicyService, ProviderRegistry, RateLimitPermit,
    RateLimiter, SecurityAuthority, SecurityToken, SessionStore, TsdbSink,
};
use async_trait::async_trait;
use regex::RegexBuilder;
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;
use std::time::Instant;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub trait ProtocolPlugin: Send + Sync {
    fn protocol(&self) -> Protocol;
    fn matches(&self, method: &str, path: &str) -> bool;
    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError>;
    fn encode(&self, response: KernelResponse, req: &RequestEnvelope) -> HttpResponse;
}

pub trait ProviderPlugin: Send + Sync {
    fn provider_type(&self) -> control_plane::ProviderType;
    fn build_upstream(
        &self,
        req: &RequestEnvelope,
        provider: &control_plane::ProviderSpec,
        key: &control_plane::KeySpec,
        address: &control_plane::AddressSpec,
    ) -> Result<UpstreamRequest, KernelError>;
    fn map_response(
        &self,
        upstream: UpstreamResponse,
        req: &RequestEnvelope,
        provider: &control_plane::ProviderSpec,
    ) -> Result<KernelResponse, KernelError>;
}

#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn send(&self, upstream: &UpstreamRequest) -> Result<UpstreamResponse, KernelError>;
}

#[derive(Debug)]
pub enum GuardStepResult {
    Continue,
    Respond(KernelResponse),
}

pub trait GuardStepPlugin: Send + Sync {
    fn step(&self) -> GuardStepKey;
    fn execute(
        &self,
        req: &mut RequestEnvelope,
        ctx: &mut GuardContext,
    ) -> Result<GuardStepResult, KernelError>;
}

#[derive(Clone)]
pub struct KernelConfig {
    pub max_provider_switches: u32,
    pub max_retries_per_provider: u32,
    pub rate_limit_enabled: bool,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_provider_switches: 5,
            max_retries_per_provider: 2,
            rate_limit_enabled: true,
        }
    }
}

pub struct Kernel {
    config: KernelConfig,
    security: Arc<dyn SecurityAuthority>,
    access: Arc<dyn AccessCheckEngine>,
    policy: Arc<dyn PolicyService>,
    providers: Arc<dyn ProviderRegistry>,
    sessions: Arc<dyn SessionStore>,
    rate_limiter: Arc<dyn RateLimiter>,
    health: Arc<dyn HealthStore>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<dyn TsdbSink>,
    context_store: Arc<dyn ContextStore>,
    forwarder: Arc<dyn Forwarder>,
    protocol_plugins: Vec<Arc<dyn ProtocolPlugin>>,
    provider_plugins: HashMap<control_plane::ProviderType, Arc<dyn ProviderPlugin>>,
    guard_plugins: HashMap<GuardStepKey, Vec<Arc<dyn GuardStepPlugin>>>,
}

#[derive(Default)]
pub struct GuardContext {
    pub token: Option<SecurityToken>,
    pub permit: Option<RateLimitPermit>,
    pub kernel_request: Option<KernelRequest>,
    pub rate_limit_applied: bool,
    pub context_applied: bool,
}

enum GuardAttempt {
    Respond(KernelResponse),
    Selection(SelectionDecision),
}

impl Kernel {
    pub fn new(
        config: KernelConfig,
        security: Arc<dyn SecurityAuthority>,
        access: Arc<dyn AccessCheckEngine>,
        policy: Arc<dyn PolicyService>,
        providers: Arc<dyn ProviderRegistry>,
        sessions: Arc<dyn SessionStore>,
        rate_limiter: Arc<dyn RateLimiter>,
        health: Arc<dyn HealthStore>,
        audit: Arc<dyn AuditSink>,
        metrics: Arc<dyn TsdbSink>,
        context_store: Arc<dyn ContextStore>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Self {
        Self {
            config,
            security,
            access,
            policy,
            providers,
            sessions,
            rate_limiter,
            health,
            audit,
            metrics,
            context_store,
            forwarder,
            protocol_plugins: Vec::new(),
            provider_plugins: HashMap::new(),
            guard_plugins: HashMap::new(),
        }
    }

    pub fn register_protocol_plugin(&mut self, plugin: Arc<dyn ProtocolPlugin>) {
        self.protocol_plugins.push(plugin);
    }

    pub fn register_provider_plugin(&mut self, plugin: Arc<dyn ProviderPlugin>) {
        self.provider_plugins.insert(plugin.provider_type(), plugin);
    }

    pub fn register_guard_plugin(&mut self, plugin: Arc<dyn GuardStepPlugin>) {
        self.guard_plugins
            .entry(plugin.step())
            .or_default()
            .push(plugin);
    }

    pub async fn handle_http(&self, req: HttpRequest) -> Result<HttpResponse, KernelError> {
        let req_path = req.path.clone();
        let protocol_plugin = self
            .protocol_plugins
            .iter()
            .find(|plugin| plugin.matches(&req.method, &req.path))
            .ok_or_else(|| KernelError::BadRequest("no protocol plugin".to_string()))?;

        let mut decoded = protocol_plugin.decode(req)?;
        if decoded.request_id.is_empty() {
            decoded.request_id = Uuid::new_v4().to_string();
        }
        let start = Instant::now();
        info!(
            request_id = %decoded.request_id,
            protocol = ?decoded.protocol,
            model = %decoded.model,
            path = %req_path,
            "kernel request start"
        );

        let requested_model = decoded.model.clone();
        let request_type = classify_request(&decoded);
        let guard_config = self.policy.guard_config();
        let pipeline = GuardPipeline::from_config(&guard_config, request_type);
        let plan = pipeline.split_for_selection();
        if !plan.has_provider_select {
            return Err(self.record_error(
                &decoded,
                KernelError::BadRequest("provider selection step missing".to_string()),
                start,
            ));
        }

        let mut guard_ctx = GuardContext::default();
        let preflight = match self.run_guard_steps(
            &mut decoded,
            &plan.preflight,
            &pipeline,
            &mut guard_ctx,
        ) {
            Ok(result) => result,
            Err(err) => return Err(self.record_error(&decoded, err, start)),
        };
        if let Some(response) = preflight {
            self.record_metrics(&decoded, "early_response", None, None, start);
            return Ok(protocol_plugin.encode(response, &decoded));
        }

        let mut exclusions = SelectionExclusions::default();
        let mut last_error: Option<KernelError> = None;
        let mut last_provider_id: Option<String> = None;

        for _ in 0..self.config.max_provider_switches {
            decoded.model = requested_model.clone();
            let selection_engine =
                SelectionEngine::new(self.access.clone(), self.health.clone(), self.rate_limiter.clone());
            let decision = match self.run_guard_attempt(
                &mut decoded,
                &plan.attempt,
                &pipeline,
                &mut guard_ctx,
                &exclusions,
                &selection_engine,
            ) {
                Ok(result) => result,
                Err(err) => return Err(self.record_error(&decoded, err, start)),
            };
            let decision = match decision {
                GuardAttempt::Respond(response) => {
                    self.record_metrics(&decoded, "early_response", None, None, start);
                    return Ok(protocol_plugin.encode(response, &decoded));
                }
                GuardAttempt::Selection(decision) => decision,
            };
            last_provider_id = Some(decision.provider.id.clone());
            debug!(
                request_id = %decoded.request_id,
                provider_id = %decision.provider.id,
                key_id = %decision.key.id,
                address_id = %decision.address.id,
                resolved_model = %decision.resolved_model,
                "provider selected"
            );

            let provider_plugin = match self.provider_plugins.get(&decision.provider.provider_type) {
                Some(plugin) => plugin,
                None => {
                    return Err(self.record_error(
                        &decoded,
                        KernelError::Upstream("missing provider plugin".to_string()),
                        start,
                    ))
                }
            };

            decoded.model = decision.resolved_model.clone();

            if let Some(session_id) = &decoded.session_id {
                if !self
                    .sessions
                    .acquire_concurrency(&decision.provider.id, session_id, decision.provider.limit_concurrent_sessions)
                {
                    exclusions.providers.insert(decision.provider.id.clone());
                    continue;
                }
            }

            let upstream = provider_plugin.build_upstream(
                &decoded,
                &decision.provider,
                &decision.key,
                &decision.address,
            );
            let upstream = match upstream {
                Ok(upstream) => upstream,
                Err(err) => {
                    last_error = Some(err);
                    self.health.record_failure(&decision.provider.id);
                    if let Some(session_id) = &decoded.session_id {
                        self.sessions
                            .release_concurrency(&decision.provider.id, session_id);
                    }
                    exclusions.providers.insert(decision.provider.id.clone());
                    continue;
                }
            };

            let mut attempt = 0;
            let max_retries = self.config.max_retries_per_provider.max(1);

            loop {
                attempt += 1;
                let response = self.forwarder.send(&upstream).await;
                match response {
                    Ok(upstream_resp) => {
                        self.health.record_success(&decision.provider.id);
                        if let Some(session_id) = &decoded.session_id {
                            self.sessions
                                .bind_on_success(session_id, &decision.provider.id);
                            self.sessions
                                .release_concurrency(&decision.provider.id, session_id);
                        }
                        self.store_context_on_success(&decoded);
                        let kernel_resp = provider_plugin.map_response(
                            upstream_resp,
                            &decoded,
                            &decision.provider,
                        )?;
                        self.audit.record(AuditEvent {
                            request_id: decoded.request_id.clone(),
                            stage: "response".to_string(),
                            detail: "success".to_string(),
                        });
                        self.record_metrics(
                            &decoded,
                            "success",
                            None,
                            Some(&decision.provider.id),
                            start,
                        );
                        return Ok(protocol_plugin.encode(kernel_resp, &decoded));
                    }
                    Err(err) => {
                        warn!(
                            request_id = %decoded.request_id,
                            provider_id = %decision.provider.id,
                            error = %err,
                            "upstream error"
                        );
                        last_error = Some(err);
                        self.health.record_failure(&decision.provider.id);
                        if let Some(session_id) = &decoded.session_id {
                            self.sessions
                                .release_concurrency(&decision.provider.id, session_id);
                        }
                        exclusions.providers.insert(decision.provider.id.clone());
                        if attempt >= max_retries {
                            break;
                        }
                    }
                }
            }
        }

        let err =
            last_error.unwrap_or_else(|| KernelError::Upstream("no available provider".to_string()));
        self.record_metrics(
            &decoded,
            "error",
            Some(error_kind(&err)),
            last_provider_id.as_deref(),
            start,
        );
        Err(err)
    }

    fn run_guard_steps(
        &self,
        req: &mut RequestEnvelope,
        steps: &[GuardStepKey],
        pipeline: &GuardPipeline,
        ctx: &mut GuardContext,
    ) -> Result<Option<KernelResponse>, KernelError> {
        for step in steps {
            match self.apply_guard_step(req, *step, pipeline, ctx)? {
                GuardStepResult::Continue => {}
                GuardStepResult::Respond(response) => return Ok(Some(response)),
            }
        }
        Ok(None)
    }

    fn run_guard_attempt(
        &self,
        req: &mut RequestEnvelope,
        steps: &[GuardStepKey],
        pipeline: &GuardPipeline,
        ctx: &mut GuardContext,
        exclusions: &SelectionExclusions,
        selector: &SelectionEngine,
    ) -> Result<GuardAttempt, KernelError> {
        let mut selection: Option<SelectionDecision> = None;
        for step in steps {
            match step {
                GuardStepKey::ProviderSelect => {
                    let snapshot = self.providers.snapshot();
                    let group = ctx
                        .token
                        .as_ref()
                        .and_then(|token| {
                            self.policy
                                .provider_group_for_token(&token.token_id)
                                .or_else(|| token.claims.get("provider_group").cloned())
                        })
                        .and_then(|group| {
                            if group.trim().is_empty() {
                                None
                            } else {
                                Some(group)
                            }
                        });
                    let criteria = SelectionCriteria {
                        model: req.model.clone(),
                        protocol: req.protocol,
                        group,
                        requires_context_1m: req.requires_context_1m,
                    };
                    let decision = if let Some(session_id) = req.session_id.as_ref() {
                        self.sessions
                            .get_binding(session_id)
                            .and_then(|provider_id| {
                                selector.select_for_provider_id(
                                    &snapshot,
                                    &provider_id,
                                    &criteria,
                                    exclusions,
                                    ctx.token.as_ref(),
                                )
                            })
                            .or_else(|| {
                                selector
                                    .select(&snapshot, &criteria, exclusions, ctx.token.as_ref())
                                    .ok()
                            })
                    } else {
                        selector
                            .select(&snapshot, &criteria, exclusions, ctx.token.as_ref())
                            .ok()
                    }
                    .ok_or_else(|| KernelError::Upstream("no available provider".to_string()))?;
                    selection = Some(decision);
                    match self.apply_guard_step(req, GuardStepKey::ProviderSelect, pipeline, ctx)? {
                        GuardStepResult::Continue => {}
                        GuardStepResult::Respond(response) => {
                            return Ok(GuardAttempt::Respond(response));
                        }
                    }
                }
                GuardStepKey::ProviderRequestFilter => {
                    if selection.is_none() {
                        return Err(KernelError::BadRequest("provider selection missing".to_string()));
                    }
                    self.filter_request_tools(req, ctx.token.as_ref())?;
                    match self.apply_guard_step(
                        req,
                        GuardStepKey::ProviderRequestFilter,
                        pipeline,
                        ctx,
                    )? {
                        GuardStepResult::Continue => {}
                        GuardStepResult::Respond(response) => {
                            return Ok(GuardAttempt::Respond(response));
                        }
                    }
                }
                _ => {
                    match self.apply_guard_step(req, *step, pipeline, ctx)? {
                        GuardStepResult::Continue => {}
                        GuardStepResult::Respond(response) => {
                            return Ok(GuardAttempt::Respond(response));
                        }
                    }
                }
            }
        }
        let selection = selection.ok_or_else(|| {
            KernelError::BadRequest("provider selection missing".to_string())
        })?;
        Ok(GuardAttempt::Selection(selection))
    }

    fn apply_guard_step(
        &self,
        req: &mut RequestEnvelope,
        step: GuardStepKey,
        _pipeline: &GuardPipeline,
        ctx: &mut GuardContext,
    ) -> Result<GuardStepResult, KernelError> {
        match step {
            GuardStepKey::Auth => {
                let token = self.security.authenticate(req.token_key.as_deref());
                if req.token_key.is_some() && token.is_none() {
                    return Err(KernelError::Unauthorized("invalid token".to_string()));
                }
                ctx.token = token;
            }
            GuardStepKey::TokenPermission => {
                if let Some(token) = ctx.token.as_ref() {
                    if token.flags.contains(control_plane::TokenFlags::DENY_ONLY) {
                        return Err(KernelError::Unauthorized("token is deny-only".to_string()));
                    }
                }
            }
            GuardStepKey::Sensitive => {
                let words = self.policy.sensitive_words();
                if !words.is_empty() {
                    let body = String::from_utf8_lossy(&req.raw_body).to_lowercase();
                    for word in words {
                        if body.contains(&word.to_lowercase()) {
                            return Err(KernelError::BadRequest(format!(
                                "sensitive word blocked: {word}"
                            )));
                        }
                    }
                }
            }
            GuardStepKey::Client => {
                let policy = self.policy.client_policy();
                match req.client_id.as_ref() {
                    Some(client_id) => {
                        if !policy.allows(client_id) {
                            return Err(KernelError::Unauthorized(
                                "client not allowed".to_string(),
                            ));
                        }
                    }
                    None => {
                        if !policy.allow_all && !policy.allow.is_empty() {
                            return Err(KernelError::BadRequest(
                                "client id required".to_string(),
                            ));
                        }
                    }
                }
            }
            GuardStepKey::Version => {
                let policy = self.policy.version_policy();
                match req.client_version.as_ref() {
                    Some(version) => {
                        if !policy.allows(version) {
                            return Err(KernelError::Unauthorized(
                                "client version not allowed".to_string(),
                            ));
                        }
                    }
                    None => {
                        if !policy.allow_all && !policy.allow.is_empty() {
                            return Err(KernelError::BadRequest(
                                "client version required".to_string(),
                            ));
                        }
                    }
                }
            }
            GuardStepKey::Probe => {
                let policy = self.policy.probe_policy();
                if policy.enabled && req.is_probe {
                    return Ok(GuardStepResult::Respond(KernelResponse {
                        status: policy.status,
                        headers: HashMap::from([(
                            String::from("content-type"),
                            String::from("application/json"),
                        )]),
                        body: ResponseBody::Bytes(policy.response_body.into_bytes()),
                    }));
                }
            }
            GuardStepKey::Model => {
                if req.model.trim().is_empty() {
                    return Err(KernelError::BadRequest("missing model".to_string()));
                }
            }
            GuardStepKey::Session => {
                self.ensure_session_id(req);
            }
            GuardStepKey::Warmup => {
                let policy = self.policy.warmup_policy();
                if policy.enabled && req.is_warmup {
                    return Ok(GuardStepResult::Respond(KernelResponse {
                        status: policy.status,
                        headers: HashMap::from([(
                            String::from("content-type"),
                            String::from("application/json"),
                        )]),
                        body: ResponseBody::Bytes(policy.response_body.into_bytes()),
                    }));
                }
            }
            GuardStepKey::RequestFilter => {
                self.apply_request_filters(req)?;
            }
            GuardStepKey::RateLimit => {
                if !ctx.rate_limit_applied && self.config.rate_limit_enabled {
                    let scope = ctx
                        .token
                        .as_ref()
                        .map(|t| format!("token:{}", t.token_id))
                        .or_else(|| req.token_key.as_ref().map(|k| format!("token_key:{k}")))
                        .unwrap_or_else(|| "token_key:anonymous".to_string());
                    let token_id = ctx
                        .token
                        .as_ref()
                        .map(|t| t.token_id.as_str())
                        .unwrap_or("anonymous");
                    let profile = self.policy.rate_limit_profile(token_id);
                    ctx.permit = Some(
                        self.rate_limiter
                            .try_acquire(&scope, profile.rpm, profile.concurrent)
                            .ok_or_else(|| {
                                KernelError::BadRequest("rate limit exceeded".to_string())
                            })?,
                    );
                    ctx.rate_limit_applied = true;
                }
            }
            GuardStepKey::MessageContext | GuardStepKey::ContextEnricher => {
                if req.kernel_request.is_none() {
                    req.kernel_request = Some(build_kernel_request(req));
                }
                self.apply_message_context(req, ctx)?;
            }
            GuardStepKey::ProviderSelect | GuardStepKey::ProviderRequestFilter => {}
        }

        if let Some(plugins) = self.guard_plugins.get(&step) {
            for plugin in plugins {
                match plugin.execute(req, ctx)? {
                    GuardStepResult::Continue => {}
                    GuardStepResult::Respond(response) => {
                        return Ok(GuardStepResult::Respond(response));
                    }
                }
            }
        }

        Ok(GuardStepResult::Continue)
    }

    fn ensure_session_id(&self, req: &mut RequestEnvelope) {
        if req.session_id.is_some() {
            return;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        req.protocol.hash(&mut hasher);
        req.model.hash(&mut hasher);
        req.raw_body.hash(&mut hasher);
        let digest = hasher.finish();
        req.session_id = Some(format!("auto:{digest:x}"));
    }

    fn filter_request_tools(
        &self,
        req: &RequestEnvelope,
        token: Option<&SecurityToken>,
    ) -> Result<(), KernelError> {
        let Some(kernel_request) = &req.kernel_request else {
            return Ok(());
        };
        let tool_names = extract_tool_names(kernel_request);
        if tool_names.is_empty() {
            return Ok(());
        }
        let policy = token
            .as_ref()
            .map(|t| self.policy.tool_policy_for_token(&t.token_id))
            .unwrap_or_else(|| self.policy.tool_policy_for_token("anonymous"));

        for name in &tool_names {
            if policy.denies(name) {
                return Err(KernelError::BadRequest(format!("tool denied: {name}")));
            }
        }
        for name in &tool_names {
            if !policy.allows(name) {
                return Err(KernelError::BadRequest(format!("tool not allowed: {name}")));
            }
        }
        Ok(())
    }

    fn apply_request_filters(&self, req: &mut RequestEnvelope) -> Result<(), KernelError> {
        let filters = self.policy.request_filters();
        if filters.is_empty() {
            return Ok(());
        }
        let mut body = String::from_utf8_lossy(&req.raw_body).to_string();
        for rule in filters {
            let escaped = regex::escape(&rule.pattern);
            let mut builder = RegexBuilder::new(&escaped);
            builder.case_insensitive(!rule.case_sensitive);
            let regex = builder
                .build()
                .map_err(|_| KernelError::BadRequest("invalid request filter".to_string()))?;
            if !regex.is_match(&body) {
                continue;
            }
            match rule.action {
                FilterAction::Block => {
                    return Err(KernelError::BadRequest(format!(
                        "request blocked by filter: {}",
                        rule.pattern
                    )));
                }
                FilterAction::Redact { replacement } => {
                    body = regex.replace_all(&body, replacement.as_str()).to_string();
                }
            }
        }
        req.raw_body = body.into_bytes();
        Ok(())
    }

    fn apply_message_context(
        &self,
        req: &mut RequestEnvelope,
        ctx: &mut GuardContext,
    ) -> Result<(), KernelError> {
        if ctx.context_applied {
            return Ok(());
        }
        let policy = self.policy.context_policy();
        if !policy.enabled {
            ctx.context_applied = true;
            return Ok(());
        }
        let Some(session_id) = req.session_id.as_ref() else {
            ctx.context_applied = true;
            return Ok(());
        };
        let context = self.context_store.load(session_id);
        if context.is_empty() {
            ctx.context_applied = true;
            ctx.kernel_request = req.kernel_request.clone();
            return Ok(());
        }
        let mut kernel_request = req.kernel_request.clone().unwrap_or_else(|| build_kernel_request(req));
        let mut messages = context_messages_to_kernel(&context);
        messages.extend(kernel_request.messages.clone());
        kernel_request.messages = messages;
        req.kernel_request = Some(kernel_request.clone());
        ctx.kernel_request = Some(kernel_request);
        ctx.context_applied = true;
        Ok(())
    }

    fn store_context_on_success(&self, req: &RequestEnvelope) {
        let policy = self.policy.context_policy();
        if !policy.enabled {
            return;
        }
        let Some(session_id) = req.session_id.as_ref() else {
            return;
        };
        let messages = match req.kernel_request.as_ref() {
            Some(kernel_request) => {
                let extracted = context_messages_from_request(kernel_request);
                if extracted.is_empty() {
                    Vec::new()
                } else {
                    extracted
                }
            }
            None => Vec::new(),
        };
        let messages = if messages.is_empty() {
            let body = String::from_utf8_lossy(&req.raw_body).to_string();
            vec![ContextMessage {
                role: "user".to_string(),
                content: body,
            }]
        } else {
            messages
        };
        if messages.is_empty() {
            return;
        }
        self.context_store.append(session_id, &messages);
        self.context_store.truncate(session_id, policy.max_messages);
    }

    fn record_metrics(
        &self,
        req: &RequestEnvelope,
        outcome: &str,
        error_kind: Option<&str>,
        provider_id: Option<&str>,
        start: Instant,
    ) {
        let mut tags = HashMap::new();
        tags.insert(
            String::from("protocol"),
            protocol_label(req.protocol).to_string(),
        );
        if !req.model.trim().is_empty() {
            tags.insert(String::from("model"), req.model.clone());
        }
        tags.insert(String::from("outcome"), outcome.to_string());
        if let Some(kind) = error_kind {
            tags.insert(String::from("error"), kind.to_string());
        }
        if let Some(provider) = provider_id {
            tags.insert(String::from("provider"), provider.to_string());
        }
        self.metrics
            .write(MetricPoint::now("requests_total", 1.0, tags.clone()));
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.metrics
            .write(MetricPoint::now("request_latency_ms", latency_ms, tags));
    }

    fn record_error(
        &self,
        req: &RequestEnvelope,
        err: KernelError,
        start: Instant,
    ) -> KernelError {
        let kind = error_kind(&err);
        self.record_metrics(req, "error", Some(kind), None, start);
        err
    }
}

fn extract_tool_names(request: &KernelRequest) -> HashSet<String> {
    let mut names = HashSet::new();
    for tool in &request.tools {
        names.insert(tool.name.clone());
    }
    for message in &request.messages {
        for block in &message.content {
            if let ContentBlock::ToolUse { name, .. } = block {
                names.insert(name.clone());
            }
        }
    }
    names
}

fn context_messages_from_request(request: &KernelRequest) -> Vec<ContextMessage> {
    request
        .messages
        .iter()
        .map(|message| {
            let mut content = String::new();
            for block in &message.content {
                match block {
                    ContentBlock::Text(text) => {
                        content.push_str(text);
                    }
                    ContentBlock::ToolUse { name, .. } => {
                        content.push_str("[tool:");
                        content.push_str(name);
                        content.push(']');
                    }
                    ContentBlock::ToolResult { name, .. } => {
                        content.push_str("[tool_result:");
                        content.push_str(name);
                        content.push(']');
                    }
                }
            }
            ContextMessage {
                role: message.role.clone(),
                content,
            }
        })
        .collect()
}

fn context_messages_to_kernel(messages: &[ContextMessage]) -> Vec<Message> {
    messages
        .iter()
        .map(|message| Message {
            role: message.role.clone(),
            content: vec![ContentBlock::Text(message.content.clone())],
        })
        .collect()
}

pub struct InMemoryForwarder;

#[async_trait]
impl Forwarder for InMemoryForwarder {
    async fn send(&self, upstream: &UpstreamRequest) -> Result<UpstreamResponse, KernelError> {
        Ok(UpstreamResponse {
            status: 200,
            headers: HashMap::new(),
            body: ResponseBody::Bytes(upstream.body.clone()),
        })
    }
}

pub fn default_guard_config() -> GuardConfig {
    GuardConfig::empty()
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::OpenAi => "openai",
        Protocol::Anthropic => "anthropic",
        Protocol::Codex => "codex",
        Protocol::Gemini => "gemini",
    }
}

fn error_kind(err: &KernelError) -> &'static str {
    match err {
        KernelError::BadRequest(_) => "bad_request",
        KernelError::Unauthorized(_) => "unauthorized",
        KernelError::Upstream(_) => "upstream",
        KernelError::Internal(_) => "internal",
    }
}
