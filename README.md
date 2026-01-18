# MCCH - Microkernel Claude Code Hub

MCCH 是 Claude Code Hub 的 Rust 重写版本，采用微内核 + 插件化架构，提供轻量级、高性能的 AI 服务。默认使用 SQLite 存储，无需外部依赖即可运行。

</div>

---

## 核心功能 Highlights

- **微内核架构**: 插件化设计，Protocol/Provider/Guard 均可扩展，核心小于 10MB
- **多协议支持**: 同时支持 Anthropic、OpenAI、Codex、Gemini 四种 API 协议
- **三级供应商选择**: Provider -> Key -> Address 细粒度调度，支持优先级 + 加权随机
- **轻量级存储**: 默认 SQLite，零依赖启动；可选 PostgreSQL + Redis 扩展
- **ACL 风格安全模型**: SID/DACL/SACL 企业级访问控制
- **Guard Pipeline**: 15 步可配置守卫管道，支持敏感词、限流、工具过滤等
- **会话亲和性**: Session 绑定到特定供应商，支持上下文历史注入
- **请求过滤规则**: 支持 Block/Redact 两种过滤动作，可自定义正则匹配

---

## 与 CCH 的差异

| 维度 | CCH (TypeScript) | MCCH (Rust) |
|------|------------------|-------------|
| **技术栈** | Next.js 16 + Hono | Axum + Tokio |
| **管理 UI** | React Admin (完整) | 静态 HTML/JS (简易) |
| **默认存储** | PostgreSQL + Redis (必须) | SQLite (可选升级) |
| **二进制大小** | ~200MB (Node.js) | ~10MB (静态链接) |
| **启动速度** | 3-5s | <1s |
| **计费统计** | 支持 | 不打算实现 |

---

## 快速开始 Quick Start

### 环境要求

- Rust 1.75+ (编译)
- 或直接下载预编译二进制

### 一键启动

```bash
# 1. 克隆项目
git clone <repository-url>
cd kernel

# 2. 编译运行
cargo build --release
./target/release/mcch-server

# 3. 或直接 cargo run
cargo run --release -- --listen 0.0.0.0:8080
```

首次启动会自动创建 `system.toml` 配置文件和 `mcch.sqlite` 数据库。

### 命令行参数

```bash
mcch-server [OPTIONS]

Options:
  -c, --config <PATH>    配置文件路径 [默认: system.toml]
  -l, --listen <ADDR>    监听地址 [默认: 0.0.0.0:8080]
  -h, --help             显示帮助信息
```

### 访问应用

启动成功后:
- **管理后台**: `http://localhost:8080` (使用 `kernel_token` 登录)
- **API 代理**: `http://localhost:8080/v1/messages`

---

## 架构说明 Architecture

### 高层架构

```
客户端请求
     |
     v
+------------------+
|   Axum Router    |  <- HTTP 入口 (CORS + Tracing)
+--------+---------+
         |
    +----+----+----+----+
    |         |         |
    v         v         v
 Admin    Proxy     Static
 Routes   Routes    Files
    |         |
    v         v
+------------------+
|   KernelManager  |  <- 核心状态管理
|  +------------+  |
|  |   Kernel   |  |  <- 请求处理内核
|  +------------+  |
|  |   Bundle   |  |  <- 控制平面配置
|  +------------+  |
|  |   Stores   |  |  <- 存储抽象层
|  +------------+  |
+------------------+
         |
    +----+----+----+
    |         |    |
    v         v    v
 SQLite   Redis  PostgreSQL
(默认)   (可选)   (可选)
```

### Crate 结构

```
kernel/
├── crates/
│   ├── microkernel/      # 微内核基础抽象
│   ├── control-plane/    # 控制平面 (配置/安全/存储)
│   ├── kernel/           # 核心内核 (Guard/Selector/Forwarder)
│   ├── kernel-space/     # 内核空间 (协议/供应商插件)
│   └── mcch-server/      # HTTP 服务器入口
├── Cargo.toml            # Workspace 配置
└── system.toml.example   # 配置示例
```

### Guard Pipeline (守卫管道)

请求处理流程经过 15 个可配置步骤:

```
Request -> [Auth] -> [TokenPermission] -> [Sensitive] -> [Client] ->
           [Model] -> [Version] -> [Probe] -> [Session] -> [Warmup] ->
           [RequestFilter] -> [RateLimit] -> [ProviderSelect] ->
           [ProviderRequestFilter] -> [MessageContext] -> Response
```

| 步骤 | 功能 |
|------|------|
| Auth | Token 认证 |
| TokenPermission | 权限检查 (deny-only 模式) |
| Sensitive | 敏感词过滤 |
| Client | 客户端 ID 校验 |
| Model | 模型字段校验 |
| Version | 客户端版本校验 |
| Probe | 探针请求处理 |
| Session | Session ID 生成/绑定 |
| Warmup | 预热请求处理 |
| RequestFilter | 请求内容过滤 |
| RateLimit | 限流检查 |
| ProviderSelect | **供应商选择** (核心) |
| ProviderRequestFilter | 工具调用过滤 |
| MessageContext | 上下文历史注入 |

### 三级供应商选择

```
Provider (供应商)
    |-- priority: 优先级
    |-- weight: 权重
    |-- group_tag: 分组标签
    |
    +-> Key (API 密钥)
           |-- priority: 优先级
           |-- weight: 权重
           |
           +-> Address (地址)
                  |-- base_url: 服务地址
                  |-- priority: 优先级
                  |-- weight: 权重
```

**选择算法**:
1. 过滤: enabled + 模型匹配 + 协议兼容 + 分组 + 健康 + ACL
2. 排序: 按 priority 升序
3. 加权随机: 同优先级内按 weight 加权选择
4. 递归: Provider -> Key -> Address

---

## 配置说明 Configuration

### 配置文件 (system.toml)

```toml
# 存储配置
[storage]
dsn = ""                          # PostgreSQL 连接串 (可选)
sqlite_path = "mcch.sqlite"       # SQLite 路径 (默认)

# 缓存配置
[cache]
redis_url = ""                    # Redis URL (可选)

# 时序数据库配置
[tsdb]
endpoint = ""                     # TSDB 端点 (可选)
sqlite_path = "mcch_tsdb.sqlite"  # TSDB SQLite 路径
timeout_ms = 1000                 # 超时时间 (毫秒)

# 安全配置
[security]
kernel_token = "change-me"        # 管理员令牌 (必须修改!)
master_key = ""                   # 主密钥 (可选)

# 运行时配置
[runtime]
thread_pool = 8                   # 线程池大小
cache_ttl_seconds = 30            # 缓存 TTL

# 引导配置
[bootstrap]
seed_on_start = true              # 启动时填充种子数据
```

### 配置项说明

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `storage.dsn` | `""` | PostgreSQL 连接串，为空时使用 SQLite |
| `storage.sqlite_path` | `mcch.sqlite` | SQLite 数据库文件路径 |
| `cache.redis_url` | `""` | Redis URL，为空时使用内存缓存 |
| `tsdb.endpoint` | `""` | 时序数据库端点，为空时使用 SQLite |
| `security.kernel_token` | `change-me` | 管理员令牌，**部署前必须修改** |
| `runtime.thread_pool` | `8` | Tokio 线程池大小 |
| `runtime.cache_ttl_seconds` | `30` | 配置缓存 TTL |
| `bootstrap.seed_on_start` | `true` | 首次启动时创建默认数据 |

---

## API 端点 API Endpoints

### 代理端点 (无需管理员认证)

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/v1/messages` | Anthropic Messages API |
| POST | `/v1/messages/count_tokens` | Token 计数 |
| POST | `/v1/chat/completions` | OpenAI Chat API |
| POST | `/v1/responses` | Codex Response API |
| GET | `/v1/models` | 可用模型列表 |

### 管理端点 (需要 Bearer Token 或 Cookie 认证)

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/admin/login` | 管理员登录 |
| GET/POST | `/api/providers` | 供应商列表/创建 |
| PUT/DELETE | `/api/providers/:id` | 供应商更新/删除 |
| POST | `/api/providers/test` | 测试供应商连接 |
| POST | `/api/providers/simulate-selection` | 模拟供应商选择 |
| GET/POST | `/api/keys` | API 密钥列表/创建 |
| PUT/DELETE | `/api/keys/:id` | 密钥更新/删除 |
| GET/POST | `/api/addresses` | 地址列表/创建 |
| PUT/DELETE | `/api/addresses/:id` | 地址更新/删除 |
| GET/POST/DELETE | `/api/links` | Key-Address 关联管理 |
| GET/PUT | `/api/policies` | 策略配置 |
| GET/POST | `/api/security/tokens` | 安全令牌管理 |
| PUT/DELETE | `/api/security/tokens/:id` | 令牌更新/删除 |
| GET/PUT | `/api/system-config` | 系统配置 |
| POST | `/api/system/reload` | 重载配置 |
| GET | `/api/audit` | 审计日志 |
| GET | `/api/metrics` | 指标数据 |
| GET | `/api/sessions/:id` | 会话详情 |
| GET | `/api/context` | 上下文查询 |

---

## 安全模型 Security Model

MCCH 采用 ACL 风格的安全模型:

### 核心概念

| 概念 | 说明 |
|------|------|
| **SID** | 安全标识符 (Security Identifier) |
| **SecurityToken** | 安全令牌，包含 user_sid、group_sids、privileges |
| **AccessMask** | 访问掩码 (READ/USE/MANAGE/ADMIN 等) |
| **ACE** | 访问控制条目 (Allow/Deny/Audit) |
| **SecurityDescriptor** | 安全描述符，包含 DACL/SACL |
| **IntegrityLevel** | 完整性级别 (Low/Medium/High/System) |

### 访问掩码 (AccessMask)

```rust
READ              = 0x0001    // 读取权限
USE               = 0x0002    // 使用权限
MANAGE            = 0x0004    // 管理权限
ADMIN             = 0x0008    // 管理员权限
PROVIDER_CREATE   = 0x0010    // 创建供应商
PROVIDER_DELETE   = 0x0020    // 删除供应商
KEY_CREATE        = 0x0040    // 创建密钥
KEY_DELETE        = 0x0080    // 删除密钥
MODEL_USE         = 0x0200    // 使用模型
TOOL_USE          = 0x0400    // 使用工具
SESSION_CREATE    = 0x0800    // 创建会话
CONFIG_READ       = 0x2000    // 读取配置
CONFIG_WRITE      = 0x4000    // 写入配置
```

---

## 策略配置 Policy Configuration

### 工具策略 (ToolPolicy)

```json
{
  "allow_all": false,
  "allow": ["code_execution", "file_read"],
  "deny": ["file_write", "shell_execute"]
}
```

### 客户端策略 (ClientPolicy)

```json
{
  "allow_all": false,
  "allow": ["claude-code", "cursor"],
  "deny": ["unknown-client"]
}
```

### 版本策略 (VersionPolicy)

```json
{
  "allow_all": false,
  "allow": ["1.0.0", "1.1.*"],
  "deny": ["0.9.*"]
}
```

### 请求过滤规则 (RequestFilterRule)

```json
{
  "pattern": "password|secret|api_key",
  "action": { "Redact": { "replacement": "[REDACTED]" } },
  "case_sensitive": false
}
```

### 限流配置 (RateLimitProfile)

```json
{
  "rpm": 60,
  "concurrent": 5
}
```

---

## 开发指南 Development

### 编译

```bash
# Debug 编译
cargo build

# Release 编译
cargo build --release

# 运行测试
cargo test

# 代码检查
cargo clippy
cargo fmt --check
```

### 目录结构

```
kernel/
├── crates/
│   ├── microkernel/          # 基础 trait 定义
│   │   └── src/lib.rs
│   ├── control-plane/        # 控制平面
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── policy.rs     # 策略定义
│   │       ├── provider.rs   # 供应商配置
│   │       ├── security.rs   # ACL 安全模型
│   │       ├── session.rs    # 会话存储
│   │       ├── rate_limit.rs # 限流
│   │       ├── audit.rs      # 审计
│   │       ├── context.rs    # 上下文存储
│   │       └── bootstrap.rs  # 引导加载
│   ├── kernel/               # 核心内核
│   │   └── src/
│   │       ├── lib.rs        # Kernel 结构体
│   │       ├── guard.rs      # Guard Pipeline
│   │       ├── selector.rs   # 供应商选择器
│   │       ├── types.rs      # 核心类型
│   │       └── forwarder.rs  # HTTP 转发器
│   ├── kernel-space/         # 内核空间
│   │   └── src/
│   │       ├── lib.rs        # Bundle 组装
│   │       ├── protocols.rs  # 协议插件
│   │       ├── providers.rs  # 供应商插件
│   │       └── discovery.rs  # 插件发现
│   └── mcch-server/          # HTTP 服务器
│       └── src/
│           ├── main.rs       # 入口点
│           ├── state.rs      # AppState
│           ├── handlers.rs   # HTTP 处理器
│           ├── error.rs      # 错误处理
│           └── static_files.rs # 静态文件
├── assets/                   # 静态资源 (编译内嵌)
├── Cargo.toml                # Workspace 配置
└── system.toml.example       # 配置示例
```

### 添加新协议插件

1. 在 `kernel-space/src/protocols.rs` 中实现 `ProtocolPlugin` trait
2. 在 `kernel-space/src/lib.rs` 中注册插件

```rust
pub struct MyProtocol;

impl ProtocolPlugin for MyProtocol {
    fn name(&self) -> &'static str { "my-protocol" }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/my-endpoint"
    }

    fn decode(&self, req: KernelHttpRequest) -> Result<RequestEnvelope, KernelError> {
        // 解码请求
    }

    fn encode(&self, resp: KernelResponse, env: &RequestEnvelope) -> KernelHttpResponse {
        // 编码响应
    }
}
```

---

## FAQ

### 1. 为什么选择 SQLite 作为默认存储?

- 零依赖，开箱即用
- 单文件部署，便于备份
- 对于中小规模使用足够
- 需要高并发时可升级到 PostgreSQL

### 2. Redis 是否必须?

不是。MCCH 默认使用内存缓存:
- 会话存储: 内存 (单机)
- 限流: 内存 (单机)
- 配置 `cache.redis_url` 后启用 Redis (支持多实例)

### 3. 如何启用 PostgreSQL?

```toml
[storage]
dsn = "postgres://user:pass@host:5432/mcch"
sqlite_path = ""  # 留空禁用 SQLite
```

### 4. 如何查看审计日志?

```bash
# API 查询
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/audit

# 或直接查询 SQLite
sqlite3 mcch.sqlite "SELECT * FROM audit_events ORDER BY id DESC LIMIT 100"
```

---

## 技术栈 Tech Stack

| 领域 | 技术 |
|------|------|
| **语言** | Rust 2021 Edition |
| **异步运行时** | Tokio 1.40 |
| **Web 框架** | Axum 0.7 |
| **HTTP 客户端** | Reqwest 0.12 (rustls-tls) |
| **序列化** | Serde + JSON/TOML |
| **数据库** | SQLite (rusqlite) / PostgreSQL (postgres) |
| **缓存** | 内存 (默认) / Redis 0.26 |
| **日志** | Tracing + tracing-subscriber |
| **CLI** | Clap 4.5 |
| **嵌入式 KV** | Sled 0.34 |
| **并发原语** | parking_lot |
| **位标志** | bitflags 2.6 |

---

