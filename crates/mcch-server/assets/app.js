const root = document.getElementById('root');

const NAV_GROUPS = [
  {
    label: '总览',
    items: [{ id: 'overview', label: '概览', desc: '系统健康与关键指标' }],
  },
  {
    label: '路由与代理',
    items: [
      { id: 'proxy', label: '代理请求', desc: '构建请求与响应检查' },
      { id: 'simulate', label: '选择器模拟', desc: '路由选择与提供商测试' },
    ],
  },
  {
    label: '资源与关联',
    items: [
      { id: 'providers', label: '提供商', desc: '上游能力与配置' },
      { id: 'keys', label: '密钥', desc: '访问密钥管理' },
      { id: 'addresses', label: '地址', desc: '可用地址池' },
      { id: 'links', label: '关联', desc: '资源绑定关系' },
    ],
  },
  {
    label: '安全与策略',
    items: [
      { id: 'policies', label: '策略', desc: '全局策略控制' },
      { id: 'tokens', label: '安全令牌', desc: '授权与凭据' },
      { id: 'sessions', label: '会话', desc: '会话绑定查询' },
      { id: 'context', label: '上下文', desc: '上下文检索' },
    ],
  },
  {
    label: '运维与审计',
    items: [
      { id: 'audit', label: '审计', desc: '操作轨迹' },
      { id: 'metrics', label: '指标', desc: '运行指标' },
    ],
  },
  {
    label: '系统',
    items: [{ id: 'system', label: '系统配置', desc: '配置与重载' }],
  },
];

const NAV_ITEMS = NAV_GROUPS.flatMap((group) => group.items);

const COLUMN_CONFIG = {
  providers: [
    { key: 'id', label: 'ID', mono: true },
    { key: 'name', label: '名称' },
    { key: 'provider_type', label: '类型' },
    {
      key: 'enabled',
      label: '状态',
      render: (value) => renderBadge(value ? '启用' : '关闭', value ? 'success' : 'warning'),
    },
    { key: 'priority', label: '优先级' },
    { key: 'weight', label: '权重' },
    {
      key: 'allowed_models',
      label: '模型数',
      render: (value) => renderBadge(Array.isArray(value) ? `${value.length}` : '0'),
    },
    {
      key: 'base_url',
      label: 'Base URL',
      render: (value) => escapeHtml(truncate(value || '-', 24)),
    },
  ],
  keys: [
    { key: 'id', label: 'ID', mono: true },
    { key: 'provider_id', label: '提供商', mono: true },
    { key: 'name', label: '名称' },
    {
      key: 'enabled',
      label: '状态',
      render: (value) => renderBadge(value ? '启用' : '关闭', value ? 'success' : 'warning'),
    },
    { key: 'priority', label: '优先级' },
    { key: 'weight', label: '权重' },
    { key: 'limit_rpm', label: 'RPM' },
  ],
  addresses: [
    { key: 'id', label: 'ID', mono: true },
    { key: 'provider_id', label: '提供商', mono: true },
    { key: 'name', label: '名称' },
    {
      key: 'enabled',
      label: '状态',
      render: (value) => renderBadge(value ? '启用' : '关闭', value ? 'success' : 'warning'),
    },
    {
      key: 'base_url',
      label: 'Base URL',
      render: (value) => escapeHtml(truncate(value || '-', 26)),
    },
  ],
  links: [
    { key: 'provider_id', label: '提供商', mono: true },
    { key: 'key_id', label: '密钥', mono: true },
    { key: 'address_id', label: '地址', mono: true },
    {
      key: 'enabled',
      label: '状态',
      render: (value) => renderBadge(value ? '启用' : '关闭', value ? 'success' : 'warning'),
    },
    { key: 'priority', label: '优先级' },
    { key: 'weight', label: '权重' },
  ],
  tokens: [
    { key: 'token_key', label: '令牌 Key', mono: true },
    {
      label: '用户',
      mono: true,
      get: (row) => (row.token ? row.token.user_sid : ''),
    },
    {
      label: '完整性',
      get: (row) => (row.token ? row.token.integrity_level : ''),
    },
    {
      label: '权限数',
      get: (row) => (row.token && row.token.privileges ? row.token.privileges.length : 0),
    },
  ],
};

const RESOURCE_CONFIGS = {
  providers: {
    title: '提供商',
    group: '资源与关联',
    idField: 'id',
    templateKind: 'provider',
    listUrl: '/api/providers',
    createUrl: '/api/providers',
    updateUrl: (id) => `/api/providers/${id}`,
    deleteUrl: (id) => `/api/providers/${id}`,
    updateMode: 'path',
    deleteMode: 'path',
    fields: [
      { key: 'id', label: 'ID', type: 'text', readonlyOnEdit: true },
      { key: 'name', label: '名称', type: 'text' },
      {
        key: 'provider_type',
        label: '类型',
        type: 'select',
        options: ['OpenAiCompatible', 'Anthropic', 'Codex', 'Gemini'],
      },
      { key: 'base_url', label: 'Base URL', type: 'text' },
      { key: 'enabled', label: '启用', type: 'boolean' },
      { key: 'priority', label: '优先级', type: 'number' },
      { key: 'weight', label: '权重', type: 'number' },
      { key: 'group_tag', label: '分组', type: 'text', optional: true },
      { key: 'join_claude_pool', label: '加入 Claude Pool', type: 'boolean' },
      { key: 'limit_rpm', label: 'RPM 限制', type: 'number' },
      { key: 'limit_concurrent', label: '并发限制', type: 'number' },
      { key: 'limit_concurrent_sessions', label: '会话并发限制', type: 'number' },
      {
        key: 'context_1m_preference',
        label: 'Context 1m',
        type: 'select',
        options: ['Disabled', 'Inherit', 'ForceEnable'],
      },
      { key: 'allowed_models', label: '允许模型', type: 'list' },
    ],
  },
  keys: {
    title: '密钥',
    group: '资源与关联',
    idField: 'id',
    templateKind: 'key',
    listUrl: '/api/keys',
    createUrl: '/api/keys',
    updateUrl: (id) => `/api/keys/${id}`,
    deleteUrl: (id) => `/api/keys/${id}`,
    updateMode: 'path',
    deleteMode: 'path',
    fields: [
      { key: 'id', label: 'ID', type: 'text', readonlyOnEdit: true },
      { key: 'provider_id', label: '提供商 ID', type: 'text' },
      { key: 'name', label: '名称', type: 'text' },
      { key: 'secret', label: '密钥', type: 'text' },
      { key: 'enabled', label: '启用', type: 'boolean' },
      { key: 'priority', label: '优先级', type: 'number' },
      { key: 'weight', label: '权重', type: 'number' },
      { key: 'limit_rpm', label: 'RPM 限制', type: 'number' },
      { key: 'limit_concurrent', label: '并发限制', type: 'number' },
      { key: 'allowed_models', label: '允许模型', type: 'list' },
    ],
  },
  addresses: {
    title: '地址',
    group: '资源与关联',
    idField: 'id',
    templateKind: 'address',
    listUrl: '/api/addresses',
    createUrl: '/api/addresses',
    updateUrl: (id) => `/api/addresses/${id}`,
    deleteUrl: (id) => `/api/addresses/${id}`,
    updateMode: 'path',
    deleteMode: 'path',
    fields: [
      { key: 'id', label: 'ID', type: 'text', readonlyOnEdit: true },
      { key: 'provider_id', label: '提供商 ID', type: 'text' },
      { key: 'name', label: '名称', type: 'text' },
      { key: 'base_url', label: 'Base URL', type: 'text' },
      { key: 'enabled', label: '启用', type: 'boolean' },
      { key: 'priority', label: '优先级', type: 'number' },
      { key: 'weight', label: '权重', type: 'number' },
      { key: 'limit_rpm', label: 'RPM 限制', type: 'number' },
      { key: 'limit_concurrent', label: '并发限制', type: 'number' },
    ],
  },
  links: {
    title: '关联',
    group: '资源与关联',
    templateKind: 'link',
    listUrl: '/api/links',
    createUrl: '/api/links',
    deleteUrl: '/api/links',
    updateMode: 'replace',
    deleteMode: 'body',
    fields: [
      { key: 'provider_id', label: '提供商 ID', type: 'text' },
      { key: 'key_id', label: '密钥 ID', type: 'text' },
      { key: 'address_id', label: '地址 ID', type: 'text' },
      { key: 'enabled', label: '启用', type: 'boolean' },
      { key: 'priority', label: '优先级', type: 'number' },
      { key: 'weight', label: '权重', type: 'number' },
    ],
  },
  tokens: {
    title: '安全令牌',
    group: '安全与策略',
    idField: 'token_key',
    templateKind: 'token',
    listUrl: '/api/security/tokens',
    createUrl: '/api/security/tokens',
    updateUrl: (id) => `/api/security/tokens/${id}`,
    deleteUrl: (id) => `/api/security/tokens/${id}`,
    updateMode: 'path',
    deleteMode: 'path',
    fields: [
      { key: 'token_key', label: '令牌 Key', type: 'text', readonlyOnEdit: true },
      { path: 'token.token_id', label: 'Token ID', type: 'text' },
      { path: 'token.user_sid', label: '用户 SID', type: 'text' },
      {
        path: 'token.integrity_level',
        label: '完整性级别',
        type: 'select',
        options: ['Low', 'Medium', 'High', 'System'],
      },
    ],
  },
};

const routes = {
  overview: renderOverview,
  proxy: renderProxy,
  simulate: renderSimulation,
  policies: renderPolicies,
  sessions: renderSessions,
  context: renderContext,
  audit: () =>
    renderReadOnlyPage({
      key: 'audit',
      title: '审计',
      url: '/api/audit',
      description: '系统操作与安全事件记录',
    }),
  metrics: renderMetrics,
  system: renderSystem,
};

let shortcutBound = false;

function getToken() {
  return localStorage.getItem('adminToken') || '';
}

function setToken(value) {
  if (value) {
    localStorage.setItem('adminToken', value);
  } else {
    localStorage.removeItem('adminToken');
  }
}

function parseHash() {
  const raw = (window.location.hash || '#overview').replace('#', '');
  const [pathPart, queryPart = ''] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean);
  const route = segments[0] || 'overview';
  const view = segments[1] || 'list';
  const params = new URLSearchParams(queryPart);
  return { route, view, params };
}

function navLabel(id) {
  const item = NAV_ITEMS.find((entry) => entry.id === id);
  return item ? item.label : id;
}

function navGroupLabel(id) {
  const group = NAV_GROUPS.find((entry) => entry.items.some((item) => item.id === id));
  return group ? group.label : '导航';
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncate(text, maxLength = 24) {
  if (!text) return '-';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

function formatDateTime(timestamp) {
  if (!timestamp && timestamp !== 0) return '-';
  const date = new Date(Number(timestamp));
  if (Number.isNaN(date.getTime())) return String(timestamp);
  return date.toLocaleString('zh-CN', { hour12: false });
}

function renderBadge(text, variant = 'info') {
  return `<span class='badge ${variant}'>${escapeHtml(text)}</span>`;
}

function readColumnValue(row, column) {
  if (column.get) return column.get(row);
  return row[column.key];
}

function renderTable(columns, rows) {
  if (!rows.length) {
    return '<div class="helper">暂无数据</div>';
  }
  const header = columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('');
  const body = rows
    .map((row) => {
      const cells = columns
        .map((column) => {
          const value = readColumnValue(row, column);
          const content = column.render ? column.render(value, row) : escapeHtml(String(value ?? ''));
          const cellClass = column.mono ? 'mono' : '';
          return `<td class='${cellClass}'>${content}</td>`;
        })
        .join('');
      return `<tr>${cells}</tr>`;
    })
    .join('');
  return `<div class='table-wrap'><table class='content-table'><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table></div>`;
}

async function apiFetch(path, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    renderLogin('AdminToken 无效或已过期');
    throw new Error('未授权');
  }
  return res;
}

async function fetchJson(path, options = {}) {
  const res = await apiFetch(path, options);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || '请求失败');
  }
  return res.json();
}

async function proxyFetch(path, options = {}, tokenKey = '') {
  const headers = options.headers ? { ...options.headers } : {};
  if (tokenKey) {
    headers.Authorization = `Bearer ${tokenKey}`;
  }
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  return fetch(path, { ...options, headers });
}

function renderLayout(content, options = {}) {
  const { route } = parseHash();
  const current = options.activeRoute || route;
  const title = options.title || navLabel(current);
  const subtitle = options.subtitle || navGroupLabel(current);
  root.innerHTML = `
    <div class='app-shell'>
      <aside class='sidebar'>
        <div class='brand'>
          <div class='brand-mark'>MCCH</div>
          <div>
            <h1 class='brand-title'>微内核控制台</h1>
            <div class='brand-subtitle'>Microkernel Claude Code Hub</div>
          </div>
        </div>
        <div class='sidebar-card'>
          <div class='sidebar-card-title'>内核运行状态</div>
          <div class='sidebar-card-value'>
            <span class='status-line'><span class='status-dot'></span>在线</span>
          </div>
        </div>
        <nav class='nav'>
          ${NAV_GROUPS.map(
            (group) => `
              <div>
                <div class='nav-group-title'>${group.label}</div>
                <div class='nav-group'>
                  ${group.items
                    .map(
                      (item) => `
                        <a class='nav-item ${item.id === current ? 'active' : ''}' href='#${item.id}'>
                          <span class='nav-item-label'>${item.label}</span>
                          <span class='nav-item-desc'>${item.desc || ''}</span>
                        </a>
                      `,
                    )
                    .join('')}
                </div>
              </div>
            `,
          ).join('')}
        </nav>
        <div class='sidebar-footer'>
          <button class='btn btn-secondary' id='commandBtn'>命令面板</button>
          <button class='btn btn-ghost' id='logoutBtn'>退出登录</button>
        </div>
      </aside>
      <main class='main'>
        <div class='topbar'>
          <div>
            <div class='page-subtitle'>${subtitle}</div>
            <h2 class='page-title'>${title}</h2>
          </div>
          <div class='topbar-actions'>
            <span class='badge success'>已连接</span>
            <button class='btn btn-ghost' id='refreshBtn'>刷新</button>
            <button class='btn btn-secondary' id='reloadBtn'>重载内核</button>
          </div>
        </div>
        <section class='content'>
          ${content}
        </section>
      </main>
    </div>
  `;

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.onclick = () => {
      setToken('');
      renderLogin();
    };
  }
  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.onclick = () => renderApp();
  }
  const reloadBtn = document.getElementById('reloadBtn');
  if (reloadBtn) {
    reloadBtn.onclick = async () => {
      await apiFetch('/api/system/reload', { method: 'POST' });
      renderApp();
    };
  }
  const commandBtn = document.getElementById('commandBtn');
  if (commandBtn) {
    commandBtn.onclick = () => openCommandPalette();
  }

  bindShortcuts();
}

function renderLogin(message = '') {
  root.innerHTML = `
    <div class='login-screen'>
      <div class='card login-card'>
        <h2 class='login-title'>Microkernel Claude Code Hub</h2>
        <p class='login-subtitle'>请输入 AdminToken 登录 MCCH。</p>
        ${message ? `<p class='helper'>${message}</p>` : ''}
        <div class='form-field' style='margin-top: 16px;'>
          <label class='form-label'>AdminToken</label>
          <input class='input' id='tokenInput' placeholder='请输入 AdminToken' />
        </div>
        <div style='margin-top: 14px;'>
          <button class='btn btn-primary' id='loginButton'>登录</button>
        </div>
      </div>
    </div>
  `;
  const loginButton = document.getElementById('loginButton');
  if (loginButton) {
    loginButton.onclick = async () => {
      const token = document.getElementById('tokenInput').value.trim();
      if (!token) return;
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      if (!res.ok) {
        renderLogin('AdminToken 无效');
        return;
      }
      setToken(token);
      window.location.hash = '#overview';
      renderApp();
    };
  }
}

async function renderOverview() {
  const [providers, keys, addresses, links, tokens, audit, metrics, config] = await Promise.all([
    fetchJson('/api/providers').catch(() => []),
    fetchJson('/api/keys').catch(() => []),
    fetchJson('/api/addresses').catch(() => []),
    fetchJson('/api/links').catch(() => []),
    fetchJson('/api/security/tokens').catch(() => []),
    fetchJson('/api/audit').catch(() => []),
    fetchJson('/api/metrics').catch(() => []),
    fetchJson('/api/system-config').catch(() => ({ keys: [] })),
  ]);

  const summary = [
    { label: '提供商', value: providers.length, meta: '上游资源' },
    { label: '密钥', value: keys.length, meta: '访问凭据' },
    { label: '地址', value: addresses.length, meta: '可用入口' },
    { label: '关联', value: links.length, meta: '路由关系' },
    { label: '令牌', value: tokens.length, meta: '安全授权' },
    { label: '审计', value: audit.length, meta: '事件记录' },
  ];

  const metricPreview = metrics.slice(0, 5);
  const auditPreview = audit.slice(0, 5);
  const timeLabel = formatDateTime(Date.now());

  const content = `
    <div class='section-header'>
      <div>
        <h3 class='section-title'>系统概览</h3>
        <div class='section-subtitle'>核心资源与运行状态总览</div>
      </div>
      <span class='badge'>同步 ${timeLabel}</span>
    </div>
    <div class='kpi-grid'>
      ${summary
        .map(
          (item) => `
          <div class='card kpi-card'>
            <div class='kpi-label'>${item.label}</div>
            <div class='kpi-value'>${item.value}</div>
            <div class='kpi-meta'>${item.meta}</div>
          </div>
        `,
        )
        .join('')}
    </div>
    <div class='grid-2'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>最新审计</div>
            <div class='card-subtitle'>最近 ${auditPreview.length} 条事件</div>
          </div>
          <button class='btn btn-ghost' data-nav='audit'>查看全部</button>
        </div>
        <pre class='code-block'>${escapeHtml(JSON.stringify(auditPreview, null, 2))}</pre>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>最新指标</div>
            <div class='card-subtitle'>最近 ${metricPreview.length} 条采样</div>
          </div>
          <button class='btn btn-ghost' data-nav='metrics'>查看全部</button>
        </div>
        <div class='metric-list'>
          ${metricPreview
            .map(
              (metric) => `
              <div class='metric-item'>
                <div>
                  <div class='metric-title'>${metric.name || 'metric'}</div>
                  <div class='metric-meta'>${formatDateTime(metric.timestamp_ms)}</div>
                </div>
                <div class='metric-value'>${metric.value ?? '-'}</div>
              </div>
            `,
            )
            .join('')}
        </div>
      </div>
    </div>
    <div class='grid-3'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>快捷入口</div>
            <div class='card-subtitle'>常用管理与配置操作</div>
          </div>
        </div>
        <div class='action-grid'>
          <a class='action-card' href='#providers'>
            <div class='action-title'>管理提供商</div>
            <div class='action-desc'>新增与调整上游提供商</div>
          </a>
          <a class='action-card' href='#keys'>
            <div class='action-title'>更新密钥</div>
            <div class='action-desc'>轮换与启用访问密钥</div>
          </a>
          <a class='action-card' href='#policies'>
            <div class='action-title'>更新策略</div>
            <div class='action-desc'>编辑全局策略与过滤</div>
          </a>
        </div>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>配置概览</div>
            <div class='card-subtitle'>系统配置键数量</div>
          </div>
        </div>
        <div class='kpi-value'>${config.keys ? config.keys.length : 0}</div>
        <div class='helper'>配置项数量，用于快速校验配置覆盖</div>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>运行态提示</div>
            <div class='card-subtitle'>内核运行与安全状态</div>
          </div>
        </div>
        <div class='status-line'><span class='status-dot'></span>Admin 通道在线</div>
        <div class='helper'>保持 token 安全，定期轮换访问密钥。</div>
      </div>
    </div>
  `;

  renderLayout(content, { title: '概览', subtitle: '系统总览' });

  document.querySelectorAll('[data-nav]').forEach((button) => {
    button.onclick = () => {
      const target = button.getAttribute('data-nav');
      if (target) {
        window.location.hash = `#${target}`;
      }
    };
  });
}

async function renderProxy() {
  const content = `
    <div class='split'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>请求构建</div>
            <div class='card-subtitle'>选择接口并提交代理请求</div>
          </div>
        </div>
        <div class='form-grid'>
          <div class='form-field'>
            <label class='form-label'>接口路径</label>
            <select class='input' id='proxyPath'>
              <option value='/v1/messages'>/v1/messages</option>
              <option value='/v1/messages/count_tokens'>/v1/messages/count_tokens</option>
              <option value='/v1/chat/completions'>/v1/chat/completions</option>
              <option value='/v1/responses'>/v1/responses</option>
              <option value='/v1/models'>/v1/models</option>
            </select>
          </div>
          <div class='form-field'>
            <label class='form-label'>令牌 Key</label>
            <input class='input' id='proxyToken' placeholder='token key' />
          </div>
          <div class='form-field'>
            <label class='form-label'>模型</label>
            <input class='input' id='proxyModel' placeholder='例如 claude-3-5-haiku' />
          </div>
        </div>
        <div class='form-grid' style='margin-top: 12px;'>
          <div class='form-field'>
            <label class='form-label'>请求头</label>
            <textarea id='proxyHeaders' class='input input-mono' placeholder='{}'></textarea>
          </div>
          <div class='form-field'>
            <label class='form-label'>请求体</label>
            <textarea id='proxyBody' class='input input-mono' placeholder='{}'></textarea>
          </div>
        </div>
        <div style='margin-top: 12px;'>
          <button class='btn btn-primary' id='proxyBtn'>发送请求</button>
        </div>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>响应结果</div>
            <div class='card-subtitle'>状态码、头部与响应体</div>
          </div>
        </div>
        <pre id='proxyResult' class='code-block'>{}</pre>
      </div>
    </div>
  `;
  renderLayout(content, { title: '代理请求', subtitle: '路由与代理' });

  document.getElementById('proxyBtn').onclick = async () => {
    const path = document.getElementById('proxyPath').value;
    const tokenKey = document.getElementById('proxyToken').value.trim();
    const modelInput = document.getElementById('proxyModel').value.trim();
    const headersText = document.getElementById('proxyHeaders').value.trim();
    const bodyText = document.getElementById('proxyBody').value.trim();

    let headers = {};
    if (headersText) {
      try {
        headers = JSON.parse(headersText);
      } catch (err) {
        alert('JSON 无效');
        return;
      }
    }

    const method = path === '/v1/models' ? 'GET' : 'POST';
    let body = undefined;
    if (method !== 'GET') {
      let payload = {};
      if (bodyText) {
        try {
          payload = JSON.parse(bodyText);
        } catch (err) {
          alert('JSON 无效');
          return;
        }
      }
      if (modelInput && (!payload.model || String(payload.model).trim() === '')) {
        payload.model = modelInput;
      }
      if (!payload.model || String(payload.model).trim() === '') {
        alert('请填写模型名称');
        return;
      }
      body = JSON.stringify(payload);
    }

    const res = await proxyFetch(path, { method, headers, body }, tokenKey);
    const text = await res.text();
    const output = {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: text,
    };
    document.getElementById('proxyResult').textContent = JSON.stringify(output, null, 2);
  };
}

async function renderSimulation() {
  const content = `
    <div class='grid-2'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>选择器模拟</div>
            <div class='card-subtitle'>验证路由选择结果</div>
          </div>
        </div>
        <div class='form-grid'>
          <div class='form-field'>
            <label class='form-label'>模型</label>
            <input class='input' id='simModel' placeholder='default' />
          </div>
          <div class='form-field'>
            <label class='form-label'>协议</label>
            <input class='input' id='simProtocol' placeholder='anthropic' />
          </div>
          <div class='form-field'>
            <label class='form-label'>分组</label>
            <input class='input' id='simGroup' placeholder='default' />
          </div>
          <div class='form-field'>
            <label class='form-label'>令牌 Key</label>
            <input class='input' id='simToken' placeholder='token key' />
          </div>
        </div>
        <div style='margin-top: 12px;'>
          <button class='btn btn-primary' id='simBtn'>模拟</button>
        </div>
        <pre class='code-block' id='simResult'>{}</pre>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>提供商测试</div>
            <div class='card-subtitle'>发起上游调用或预览请求</div>
          </div>
        </div>
        <div class='form-grid'>
          <div class='form-field'>
            <label class='form-label'>提供商 ID</label>
            <input class='input' id='testProviderId' placeholder='provider_id' />
          </div>
          <div class='form-field'>
            <label class='form-label'>密钥 ID</label>
            <input class='input' id='testKeyId' placeholder='key_id' />
          </div>
          <div class='form-field'>
            <label class='form-label'>地址 ID</label>
            <input class='input' id='testAddressId' placeholder='address_id' />
          </div>
          <div class='form-field'>
            <label class='form-label'>模型</label>
            <input class='input' id='testModel' placeholder='default' />
          </div>
          <div class='form-field'>
            <label class='form-label'>协议</label>
            <input class='input' id='testProtocol' placeholder='anthropic' />
          </div>
          <div class='form-field'>
            <label class='form-label'>流式</label>
            <select class='input' id='testStream'>
              <option value='false'>关闭</option>
              <option value='true'>开启</option>
            </select>
          </div>
          <div class='form-field'>
            <label class='form-label'>仅预览</label>
            <select class='input' id='testDryRun'>
              <option value='false'>否</option>
              <option value='true'>是</option>
            </select>
          </div>
        </div>
        <div style='margin-top: 12px;'>
          <button class='btn btn-primary' id='testBtn'>测试</button>
        </div>
        <pre class='code-block' id='testResult'>{}</pre>
      </div>
    </div>
  `;
  renderLayout(content, { title: '选择器模拟', subtitle: '路由与代理' });

  document.getElementById('simBtn').onclick = async () => {
    const modelValue = document.getElementById('simModel').value.trim();
    const protocolValue = document.getElementById('simProtocol').value.trim();
    const groupValue = document.getElementById('simGroup').value.trim();
    const tokenValue = document.getElementById('simToken').value.trim();
    const payload = {
      model: modelValue || 'default',
      protocol: protocolValue || 'anthropic',
      group: groupValue || null,
      token_key: tokenValue || null,
    };
    const res = await apiFetch('/api/providers/simulate-selection', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    document.getElementById('simResult').textContent = JSON.stringify(data, null, 2);
  };

  document.getElementById('testBtn').onclick = async () => {
    const payload = {
      provider_id: document.getElementById('testProviderId').value.trim(),
      key_id: document.getElementById('testKeyId').value.trim(),
      address_id: document.getElementById('testAddressId').value.trim(),
      model: document.getElementById('testModel').value.trim() || 'default',
      protocol: document.getElementById('testProtocol').value.trim() || 'anthropic',
      stream: document.getElementById('testStream').value === 'true',
      dry_run: document.getElementById('testDryRun').value === 'true',
    };
    const res = await apiFetch('/api/providers/test', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    document.getElementById('testResult').textContent = JSON.stringify(data, null, 2);
  };
}

function buildResourceListHash(route) {
  return `#${route}`;
}

function buildResourceNewHash(route) {
  return `#${route}/new`;
}

function buildResourceConfigHash(route, row) {
  if (route === 'links') {
    const query = new URLSearchParams({
      provider_id: row.provider_id || '',
      key_id: row.key_id || '',
      address_id: row.address_id || '',
    });
    return `#${route}/config?${query.toString()}`;
  }
  const config = RESOURCE_CONFIGS[route];
  const query = new URLSearchParams({ id: row[config.idField] || '' });
  return `#${route}/config?${query.toString()}`;
}

function getValueByPath(target, path) {
  if (!path) return undefined;
  const parts = path.split('.');
  let current = target;
  for (const key of parts) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[key];
  }
  return current;
}

function setValueByPath(target, path, value) {
  if (!path) return;
  const parts = path.split('.');
  let current = target;
  parts.slice(0, -1).forEach((key) => {
    if (!current[key] || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key];
  });
  current[parts[parts.length - 1]] = value;
}

function formatFieldValue(payload, field) {
  const path = field.path || field.key;
  const value = getValueByPath(payload, path);
  if (field.type === 'list') {
    return Array.isArray(value) ? value.join(', ') : '';
  }
  if (field.type === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (value === null || value === undefined) return '';
  return String(value);
}

function parseFieldValue(field, raw) {
  const trimmed = raw.trim();
  if (field.type === 'list') {
    if (!trimmed) return [];
    return trimmed
      .split(/[,\n]/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  if (field.type === 'number') {
    if (!trimmed && field.optional) return null;
    const value = Number(trimmed);
    return Number.isNaN(value) ? 0 : value;
  }
  if (field.type === 'boolean') {
    return raw === 'true';
  }
  if (field.optional && trimmed === '') return null;
  return raw;
}

function renderField(field, payload, isEditing) {
  const path = field.path || field.key;
  const value = formatFieldValue(payload, field);
  const disabled = isEditing && field.readonlyOnEdit;
  const baseAttrs = `class='input' data-field-path='${path}' data-field-type='${field.type}' data-field-optional='${field.optional ? 'true' : 'false'}' ${
    disabled ? 'disabled' : ''
  }`;

  let input = '';
  if (field.type === 'select') {
    input = `
      <select ${baseAttrs}>
        ${(field.options || [])
          .map(
            (option) =>
              `<option value='${option}' ${option === value ? 'selected' : ''}>${option}</option>`,
          )
          .join('')}
      </select>
    `;
  } else if (field.type === 'boolean') {
    input = `
      <select ${baseAttrs}>
        <option value='true' ${value === 'true' ? 'selected' : ''}>是</option>
        <option value='false' ${value === 'false' ? 'selected' : ''}>否</option>
      </select>
    `;
  } else {
    input = `<input ${baseAttrs} value='${escapeHtml(value)}' placeholder='${field.placeholder || ''}' />`;
  }

  return `
    <div class='form-field'>
      <label class='form-label'>${field.label}</label>
      ${input}
      ${field.helper ? `<div class='helper'>${field.helper}</div>` : ''}
    </div>
  `;
}

function updateFormFromPayload(payload, fields) {
  fields.forEach((field) => {
    const path = field.path || field.key;
    const input = document.querySelector(`[data-field-path='${path}']`);
    if (!input) return;
    input.value = formatFieldValue(payload, field);
  });
}

async function fetchTemplate(config) {
  try {
    return await fetchJson(`/api/templates/${config.templateKind}`);
  } catch (err) {
    return null;
  }
}

async function renderResourceList(route) {
  const config = RESOURCE_CONFIGS[route];
  const data = await fetchJson(config.listUrl);
  const getIdValue = (row) => (config.idField ? row[config.idField] || '' : '');
  const actionColumn = {
    label: '操作',
    render: (_, row) => `
      <div class='table-actions'>
        <button class='btn btn-ghost btn-sm' data-action='config' data-route='${route}' data-id='${encodeURIComponent(
      getIdValue(row),
    )}' data-payload='${encodeURIComponent(JSON.stringify(row))}'>配置</button>
        <button class='btn btn-danger btn-sm' data-action='delete' data-route='${route}' data-id='${encodeURIComponent(
      getIdValue(row),
    )}' data-payload='${encodeURIComponent(JSON.stringify(row))}'>删除</button>
      </div>
    `,
  };
  const columns = [...(COLUMN_CONFIG[route] || []), actionColumn];
  const content = `
    <div class='section-header'>
      <div>
        <h3 class='section-title'>${config.title}列表</h3>
        <div class='section-subtitle'>共 ${data.length} 条记录</div>
      </div>
      <div class='topbar-actions'>
        <button class='btn btn-ghost' id='refreshData'>刷新</button>
        <button class='btn btn-primary' id='createNew'>新建</button>
      </div>
    </div>
    <div class='card'>
      ${renderTable(columns, data)}
    </div>
  `;
  renderLayout(content, { title: config.title, subtitle: config.group, activeRoute: route });

  document.getElementById('refreshData').onclick = () => renderApp();
  document.getElementById('createNew').onclick = () => {
    window.location.hash = buildResourceNewHash(route);
  };

  document.querySelectorAll('[data-action="config"]').forEach((button) => {
    button.onclick = () => {
      const payload = JSON.parse(decodeURIComponent(button.dataset.payload || '{}'));
      window.location.hash = buildResourceConfigHash(route, payload);
    };
  });

  document.querySelectorAll('[data-action="delete"]').forEach((button) => {
    button.onclick = async () => {
      const payload = JSON.parse(decodeURIComponent(button.dataset.payload || '{}'));
      if (!confirm(`确定删除${config.title}？`)) return;
      if (config.deleteMode === 'body') {
        await apiFetch(config.deleteUrl, { method: 'DELETE', body: JSON.stringify(payload) });
      } else {
        const id = payload[config.idField];
        await apiFetch(config.deleteUrl(id), { method: 'DELETE' });
      }
      renderApp();
    };
  });
}

async function renderResourceConfig(route, view, params) {
  const config = RESOURCE_CONFIGS[route];
  const isNew = view === 'new';
  const list = await fetchJson(config.listUrl);
  let payload = null;
  let originalKey = null;

  if (isNew) {
    payload = await fetchTemplate(config);
    if (!payload && list.length > 0) {
      payload = JSON.parse(JSON.stringify(list[0]));
    }
    if (!payload) {
      payload = {};
    }
    if (config.idField && payload[config.idField]) {
      payload[config.idField] = '';
    }
  } else if (route === 'links') {
    const providerId = params.get('provider_id');
    const keyId = params.get('key_id');
    const addressId = params.get('address_id');
    payload = list.find(
      (item) =>
        item.provider_id === providerId &&
        item.key_id === keyId &&
        item.address_id === addressId,
    );
    originalKey = { provider_id: providerId, key_id: keyId, address_id: addressId };
  } else {
    const id = params.get('id');
    payload = list.find((item) => item[config.idField] === id);
    originalKey = { id };
  }

  if (!payload) {
    renderLayout(
      `<div class='card'><div class='card-header'><div><div class='card-title'>找不到记录</div><div class='card-subtitle'>请返回列表重新选择。</div></div></div></div>`,
      { title: config.title, subtitle: config.group, activeRoute: route },
    );
    return;
  }

  const title = isNew ? `新建${config.title}` : `${config.title}配置`;
  const content = `
    <div class='section-header'>
      <div>
        <h3 class='section-title'>${title}</h3>
        <div class='section-subtitle'>在表格与配置页之间切换，降低操作复杂度</div>
      </div>
      <div class='topbar-actions'>
        <button class='btn btn-ghost' id='backList'>返回列表</button>
        <button class='btn btn-secondary' id='applyJson'>应用 JSON</button>
        <button class='btn btn-primary' id='saveConfig'>保存</button>
      </div>
    </div>
    <div class='grid-2'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>基础字段</div>
            <div class='card-subtitle'>常用字段可直接编辑</div>
          </div>
        </div>
        <div class='form-grid'>
          ${config.fields.map((field) => renderField(field, payload, !isNew)).join('')}
        </div>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>完整配置</div>
            <div class='card-subtitle'>高级配置请直接修改 JSON</div>
          </div>
        </div>
        <textarea id='resourceJson' class='input input-mono'></textarea>
        <div class='helper'>修改 JSON 后点击“应用 JSON”同步到表单。</div>
      </div>
    </div>
  `;

  renderLayout(content, { title: config.title, subtitle: config.group, activeRoute: route });

  let currentPayload = JSON.parse(JSON.stringify(payload));
  const jsonEditor = document.getElementById('resourceJson');
  const syncJson = () => {
    jsonEditor.value = JSON.stringify(currentPayload, null, 2);
  };

  syncJson();
  updateFormFromPayload(currentPayload, config.fields);

  document.querySelectorAll('[data-field-path]').forEach((input) => {
    const fieldPath = input.dataset.fieldPath;
    const field = config.fields.find((entry) => (entry.path || entry.key) === fieldPath);
    const handler = () => {
      const value = parseFieldValue(field, input.value);
      setValueByPath(currentPayload, fieldPath, value);
      syncJson();
    };
    input.addEventListener('input', handler);
    input.addEventListener('change', handler);
  });

  document.getElementById('applyJson').onclick = () => {
    const nextPayload = parseJsonInput('resourceJson');
    if (!nextPayload) return;
    currentPayload = nextPayload;
    updateFormFromPayload(currentPayload, config.fields);
  };

  document.getElementById('backList').onclick = () => {
    window.location.hash = buildResourceListHash(route);
  };

  document.getElementById('saveConfig').onclick = async () => {
    const nextPayload = parseJsonInput('resourceJson');
    if (!nextPayload) return;
    if (!isNew) {
      if (route === 'links' && originalKey) {
        await apiFetch(config.deleteUrl, {
          method: 'DELETE',
          body: JSON.stringify(originalKey),
        });
        await apiFetch(config.createUrl, {
          method: 'POST',
          body: JSON.stringify(nextPayload),
        });
      } else if (config.updateMode === 'path') {
        if (!originalKey || !originalKey.id) {
          alert('缺少更新所需的 ID');
          return;
        }
        if (config.idField) {
          nextPayload[config.idField] = originalKey.id;
        }
        await apiFetch(config.updateUrl(originalKey.id), {
          method: 'PUT',
          body: JSON.stringify(nextPayload),
        });
      }
    } else {
      await apiFetch(config.createUrl, {
        method: 'POST',
        body: JSON.stringify(nextPayload),
      });
    }
    window.location.hash = buildResourceListHash(route);
  };
}

async function renderPolicies() {
  const data = await fetchJson('/api/policies');
  const content = `
    <div class='card'>
      <div class='card-header'>
        <div>
          <div class='card-title'>策略编辑</div>
          <div class='card-subtitle'>更新全局策略与过滤规则</div>
        </div>
      </div>
      <textarea id='policyJson' class='input input-mono'></textarea>
      <div style='margin-top: 12px;'>
        <button class='btn btn-primary' id='savePolicies'>保存</button>
      </div>
    </div>
  `;
  renderLayout(content, { title: '策略', subtitle: '安全与策略' });

  document.getElementById('policyJson').value = JSON.stringify(data, null, 2);
  document.getElementById('savePolicies').onclick = async () => {
    const payload = parseJsonInput('policyJson');
    if (!payload) return;
    await apiFetch('/api/policies', { method: 'PUT', body: JSON.stringify(payload) });
    renderApp();
  };
}

async function renderSessions() {
  const content = `
    <div class='card'>
      <div class='card-header'>
        <div>
          <div class='card-title'>会话查询</div>
          <div class='card-subtitle'>根据会话 ID 查询绑定信息</div>
        </div>
      </div>
      <div class='form-grid'>
        <div class='form-field'>
          <label class='form-label'>会话 ID</label>
          <input class='input' id='sessionId' placeholder='session_id' />
        </div>
      </div>
      <div style='margin-top: 12px;'>
        <button class='btn btn-primary' id='sessionBtn'>查询</button>
      </div>
      <pre class='code-block' id='sessionResult'>{}</pre>
    </div>
  `;
  renderLayout(content, { title: '会话', subtitle: '安全与策略' });

  document.getElementById('sessionBtn').onclick = async () => {
    const id = document.getElementById('sessionId').value.trim();
    if (!id) return;
    const res = await apiFetch(`/api/sessions/${id}`);
    const data = await res.json();
    document.getElementById('sessionResult').textContent = JSON.stringify(data, null, 2);
  };
}

async function renderContext() {
  const content = `
    <div class='card'>
      <div class='card-header'>
        <div>
          <div class='card-title'>上下文查询</div>
          <div class='card-subtitle'>根据会话 ID 获取上下文</div>
        </div>
      </div>
      <div class='form-grid'>
        <div class='form-field'>
          <label class='form-label'>会话 ID</label>
          <input class='input' id='contextId' placeholder='session_id' />
        </div>
      </div>
      <div style='margin-top: 12px;'>
        <button class='btn btn-primary' id='contextBtn'>查询</button>
      </div>
      <pre class='code-block' id='contextResult'>[]</pre>
    </div>
  `;
  renderLayout(content, { title: '上下文', subtitle: '安全与策略' });

  document.getElementById('contextBtn').onclick = async () => {
    const id = document.getElementById('contextId').value.trim();
    if (!id) return;
    const res = await apiFetch(`/api/context?session_id=${encodeURIComponent(id)}`);
    const data = await res.json();
    document.getElementById('contextResult').textContent = JSON.stringify(data, null, 2);
  };
}

async function renderReadOnlyPage(config) {
  const data = await fetchJson(config.url);
  const content = `
    <div class='card'>
      <div class='card-header'>
        <div>
          <div class='card-title'>${config.title}</div>
          <div class='card-subtitle'>${config.description}</div>
        </div>
      </div>
      <pre class='code-block'>${escapeHtml(JSON.stringify(data, null, 2))}</pre>
    </div>
  `;
  renderLayout(content, { title: config.title, subtitle: '运维与审计' });
}

async function renderMetrics() {
  const data = await fetchJson('/api/metrics');
  const columns = [
    { key: 'name', label: '指标', mono: true },
    { key: 'value', label: '数值' },
    { key: 'timestamp_ms', label: '时间', render: (value) => escapeHtml(formatDateTime(value)) },
    {
      key: 'tags',
      label: '标签',
      render: (value) => escapeHtml(JSON.stringify(value || {})),
    },
  ];
  const content = `
    <div class='card'>
      <div class='card-header'>
        <div>
          <div class='card-title'>指标数据</div>
          <div class='card-subtitle'>当前采样的指标列表</div>
        </div>
      </div>
      ${renderTable(columns, data)}
    </div>
  `;
  renderLayout(content, { title: '指标', subtitle: '运维与审计' });
}

async function renderSystem() {
  const data = await fetchJson('/api/system-config');
  const content = `
    <div class='grid-2'>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>系统配置</div>
            <div class='card-subtitle'>编辑并保存配置内容</div>
          </div>
        </div>
        <textarea id='systemConfig' class='input input-mono'></textarea>
        <div style='margin-top: 12px;'>
          <button class='btn btn-primary' id='saveConfig'>保存并重载</button>
          <button class='btn btn-secondary' id='reloadOnly' style='margin-left: 8px;'>仅重载</button>
        </div>
      </div>
      <div class='card'>
        <div class='card-header'>
          <div>
            <div class='card-title'>配置键</div>
            <div class='card-subtitle'>当前配置包含的键</div>
          </div>
        </div>
        <pre class='code-block'>${escapeHtml(JSON.stringify(data.keys || [], null, 2))}</pre>
      </div>
    </div>
  `;
  renderLayout(content, { title: '系统配置', subtitle: '系统' });

  document.getElementById('systemConfig').value = data.content || '';
  document.getElementById('saveConfig').onclick = async () => {
    const contentValue = document.getElementById('systemConfig').value;
    await apiFetch('/api/system-config', {
      method: 'PUT',
      body: JSON.stringify({ content: contentValue }),
    });
    renderApp();
  };
  document.getElementById('reloadOnly').onclick = async () => {
    await apiFetch('/api/system/reload', { method: 'POST' });
    renderApp();
  };
}

function parseJsonInput(id) {
  const text = document.getElementById(id).value.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (err) {
    alert('JSON 无效');
    return null;
  }
}

function openCommandPalette() {
  closeCommandPalette();
  const overlay = document.createElement('div');
  overlay.className = 'command-overlay';
  overlay.innerHTML = `
    <div class='command-panel'>
      <input class='input' id='commandInput' placeholder='搜索页面或命令' />
      <div class='command-list' id='commandList'></div>
    </div>
  `;
  document.body.appendChild(overlay);
  const input = document.getElementById('commandInput');
  const list = document.getElementById('commandList');

  const actions = [
    ...NAV_ITEMS.map((item) => ({
      id: `nav-${item.id}`,
      title: item.label,
      desc: item.desc || '',
      run: () => {
        window.location.hash = `#${item.id}`;
        renderApp();
      },
    })),
    {
      id: 'reload',
      title: '系统重载',
      desc: '重新加载内核与配置',
      run: async () => {
        await apiFetch('/api/system/reload', { method: 'POST' });
        renderApp();
      },
    },
    {
      id: 'logout',
      title: '退出登录',
      desc: '清除管理员登录状态',
      run: () => {
        setToken('');
        renderLogin();
      },
    },
  ];

  const renderList = (keyword) => {
    const lower = keyword.toLowerCase();
    list.innerHTML = actions
      .filter((action) => action.title.toLowerCase().includes(lower))
      .map(
        (action) => `
          <div class='command-item' data-action='${action.id}'>
            <div class='command-title'>${action.title}</div>
            <div class='command-desc'>${action.desc}</div>
          </div>
        `,
      )
      .join('');

    list.querySelectorAll('.command-item').forEach((item) => {
      item.onclick = () => {
        const action = actions.find((entry) => entry.id === item.dataset.action);
        if (action) {
          closeCommandPalette();
          action.run();
        }
      };
    });
  };

  renderList('');
  input.focus();
  input.addEventListener('input', () => renderList(input.value));
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) closeCommandPalette();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeCommandPalette();
  });
}

function closeCommandPalette() {
  const overlay = document.querySelector('.command-overlay');
  if (overlay) overlay.remove();
}

function bindShortcuts() {
  if (shortcutBound) return;
  shortcutBound = true;
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openCommandPalette();
    }
  });
}

async function renderApp() {
  closeCommandPalette();
  const token = getToken();
  if (!token) {
    renderLogin();
    return;
  }

  const { route, view, params } = parseHash();
  try {
    if (RESOURCE_CONFIGS[route]) {
      if (view === 'config' || view === 'new') {
        await renderResourceConfig(route, view, params);
      } else {
        await renderResourceList(route);
      }
      return;
    }
    const renderer = routes[route] || routes.overview;
    await renderer();
  } catch (err) {
    renderLayout(
      `
        <div class='card'>
          <div class='card-header'>
            <div>
              <div class='card-title'>加载失败</div>
              <div class='card-subtitle'>${escapeHtml(err.message || '发生错误')}</div>
            </div>
          </div>
        </div>
      `,
      { title: '错误', subtitle: navGroupLabel(route) },
    );
  }
}

window.addEventListener('hashchange', renderApp);
renderApp();
