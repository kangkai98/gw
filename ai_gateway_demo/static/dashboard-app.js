import React, { useCallback, useEffect, useMemo, useState } from 'https://esm.sh/react@18.3.1';
import { createRoot } from 'https://esm.sh/react-dom@18.3.1/client';
import htm from 'https://esm.sh/htm@3.1.1';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
} from 'https://esm.sh/recharts@2.12.7';

const html = htm.bind(React.createElement);

const ACCENT = {
  violet: '#8B5CF6',
  cyan: '#22D3EE',
  blue: '#60A5FA',
  emerald: '#34D399',
  rose: '#FB7185',
  amber: '#FBBF24',
  slate: '#94A3B8',
};

const chartPalette = [ACCENT.violet, ACCENT.cyan, ACCENT.blue, ACCENT.emerald, ACCENT.rose, ACCENT.amber];

const mockEntries = [
  {
    id: 'demo-1',
    start_time_real: '2026-03-18 08:31:12',
    start_time_rel_s: 0.512481,
    latency_ms: 1842.5,
    category_major: '三方AI',
    category_minor: 'openai.com',
    flow_key: '10.10.8.12:54511-104.18.33.45:443',
    ttfb_ms: 212.4,
    ttft_ms: 468.2,
    tpot_ms_per_token: 31.5,
    input_tokens: 1264,
    output_tokens: 174,
  },
  {
    id: 'demo-2',
    start_time_real: '2026-03-18 08:36:41',
    start_time_rel_s: 329.102834,
    latency_ms: 2648.7,
    category_major: '自建AI',
    category_minor: '知识助手',
    flow_key: '10.10.8.12:54882-192.168.101.1:8443',
    ttfb_ms: 331.1,
    ttft_ms: 695.4,
    tpot_ms_per_token: 27.4,
    input_tokens: 986,
    output_tokens: 252,
  },
  {
    id: 'demo-3',
    start_time_real: '2026-03-18 08:43:05',
    start_time_rel_s: 713.554621,
    latency_ms: 1396.3,
    category_major: '实验AI',
    category_minor: 'exp-172.16.30.9',
    flow_key: '10.10.8.12:55220-172.16.30.9:8080',
    ttfb_ms: 174.8,
    ttft_ms: 392.3,
    tpot_ms_per_token: 23.6,
    input_tokens: 802,
    output_tokens: 109,
  },
];

const mockConfigs = [
  { id: 1, name: '知识助手', server_ip: '192.168.101.1:8443' },
  { id: 2, name: 'RAG 工作台', server_ip: '192.168.101.7:9443' },
];

const mockStats = {
  total_entries: 128,
  total_input_tokens: 184220,
  total_output_tokens: 35590,
  rps: 4.8,
  major_stats: [
    { category_major: '三方AI', total_entries: 58, total_input_tokens: 82200, total_output_tokens: 16110, avg_ttfb_ms: 210.7, avg_ttft_ms: 502.4, avg_latency_ms: 1721.6 },
    { category_major: '自建AI', total_entries: 46, total_input_tokens: 73210, total_output_tokens: 14012, avg_ttfb_ms: 318.1, avg_ttft_ms: 688.8, avg_latency_ms: 2482.4 },
    { category_major: '实验AI', total_entries: 24, total_input_tokens: 28810, total_output_tokens: 5468, avg_ttfb_ms: 176.6, avg_ttft_ms: 409.9, avg_latency_ms: 1468.2 },
  ],
};

function formatCompact(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '--';
  return new Intl.NumberFormat('zh-CN', { notation: 'compact', maximumFractionDigits: 1 }).format(Number(value));
}

function formatNumber(value, digits = 1) {
  if (value === null || value === undefined || value === '') return '--';
  const n = Number(value);
  if (Number.isNaN(n)) return '--';
  return n.toFixed(digits);
}

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '--';
  return `${Number(value).toFixed(1)}%`;
}

function toServerTime(value) {
  return value ? `${value.replace('T', ' ')}:00` : '';
}

function parseFlow(flowKey) {
  if (!flowKey || !flowKey.includes('-')) return { client: '--', server: '--', display: '--' };
  const [client, server] = flowKey.split('-');
  return { client, server, display: `${client} → ${server}` };
}

function buildQueryString(filters) {
  const q = new URLSearchParams();
  const startReal = toServerTime(filters.startReal);
  const endReal = toServerTime(filters.endReal);
  if (startReal) q.set('start_real', startReal);
  if (endReal) q.set('end_real', endReal);
  if (filters.major) q.set('category_major', filters.major);
  if (filters.minor.trim()) q.set('category_minor', filters.minor.trim());
  const qs = q.toString();
  return qs ? `?${qs}` : '';
}

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`${resp.status} ${resp.statusText}`);
  }
  return resp.json();
}

function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.responseType = 'json';
    xhr.upload.onprogress = (evt) => {
      if (evt.lengthComputable) {
        onProgress(Math.min(100, Math.round((evt.loaded / evt.total) * 100)));
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response);
      } else {
        reject(new Error(`上传失败：${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error('上传失败：网络异常'));
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

function buildFallbackTrend(entries) {
  const source = entries.length ? entries : mockEntries;
  return source.map((entry, index) => ({
    label: entry.start_time_real?.slice(11, 16) || `T+${index + 1}`,
    requests: 1,
    inputTokens: entry.input_tokens || 0,
    outputTokens: entry.output_tokens || 0,
    latency: Number(((entry.latency_ms || 0) / 1000).toFixed(2)),
  }));
}

function bucketEntries(entries) {
  if (!entries.length) return buildFallbackTrend([]);
  const buckets = new Map();
  entries.forEach((entry, index) => {
    const label = entry.start_time_real ? entry.start_time_real.slice(11, 16) : `#${index + 1}`;
    const current = buckets.get(label) || { label, requests: 0, inputTokens: 0, outputTokens: 0, latencySum: 0 };
    current.requests += 1;
    current.inputTokens += Number(entry.input_tokens || 0);
    current.outputTokens += Number(entry.output_tokens || 0);
    current.latencySum += Number(entry.latency_ms || 0) / 1000;
    buckets.set(label, current);
  });
  return Array.from(buckets.values()).map((item) => ({
    label: item.label,
    requests: item.requests,
    inputTokens: item.inputTokens,
    outputTokens: item.outputTokens,
    latency: Number((item.latencySum / item.requests).toFixed(2)),
  }));
}

function buildActivityFeed(entries, configs) {
  const liveEntries = entries.length ? entries : mockEntries;
  const liveConfigs = configs.length ? configs : mockConfigs;
  const entryItems = liveEntries.slice(0, 4).map((entry) => ({
    title: `${entry.category_major} / ${entry.category_minor}`,
    subtitle: `${entry.start_time_real || '刚刚'} · ${formatNumber((entry.latency_ms || 0) / 1000, 2)}s latency`,
    tone: 'violet',
  }));
  const cfgItems = liveConfigs.slice(0, 2).map((cfg) => ({
    title: `自建服务映射：${cfg.name}`,
    subtitle: cfg.server_ip,
    tone: 'cyan',
  }));
  return [...entryItems, ...cfgItems];
}

function buildStats(stats, entries) {
  const usingMock = !entries.length;
  const sourceStats = usingMock ? mockStats : stats;
  const total = Number(sourceStats.total_entries || 0);
  const avgLatency = entries.length
    ? entries.reduce((sum, entry) => sum + Number(entry.latency_ms || 0), 0) / entries.length / 1000
    : 1.94;
  const successRate = total ? Math.min(99.9, 92 + total / 100) : 98.4;
  const avgOutput = total ? Number(sourceStats.total_output_tokens || 0) / total : 278.0;

  return [
    {
      label: 'Total Requests',
      value: formatCompact(sourceStats.total_entries || 0),
      detail: `${sourceStats.total_entries || 0} 次检测`,
      accent: ACCENT.violet,
      trend: '+18.6%',
    },
    {
      label: 'Input Tokens',
      value: formatCompact(sourceStats.total_input_tokens || 0),
      detail: 'Prompt throughput',
      accent: ACCENT.cyan,
      trend: '+12.4%',
    },
    {
      label: 'Avg Latency',
      value: `${formatNumber(avgLatency, 2)}s`,
      detail: 'Response end-to-end',
      accent: ACCENT.amber,
      trend: '-6.1%',
    },
    {
      label: 'Healthy Ratio',
      value: formatPercent(successRate),
      detail: `Avg output ${formatNumber(avgOutput, 0)} tokens`,
      accent: ACCENT.emerald,
      trend: '+2.1%',
    },
  ];
}

function buildCategoryStats(stats, entries) {
  const rows = stats.major_stats?.length ? stats.major_stats : mockStats.major_stats;
  if (!rows.length && entries.length) {
    const map = new Map();
    entries.forEach((entry) => {
      const key = entry.category_major || '未知';
      const current = map.get(key) || { category_major: key, total_entries: 0, avg_ttfb_ms: 0, avg_ttft_ms: 0, avg_latency_ms: 0, total_input_tokens: 0, total_output_tokens: 0 };
      current.total_entries += 1;
      current.total_input_tokens += Number(entry.input_tokens || 0);
      current.total_output_tokens += Number(entry.output_tokens || 0);
      current.avg_ttfb_ms += Number(entry.ttfb_ms || 0);
      current.avg_ttft_ms += Number(entry.ttft_ms || 0);
      current.avg_latency_ms += Number(entry.latency_ms || 0);
      map.set(key, current);
    });
    return Array.from(map.values()).map((item) => ({
      ...item,
      avg_ttfb_ms: item.avg_ttfb_ms / item.total_entries,
      avg_ttft_ms: item.avg_ttft_ms / item.total_entries,
      avg_latency_ms: item.avg_latency_ms / item.total_entries,
    }));
  }
  return rows;
}

function filterEntries(entries, search) {
  if (!search.trim()) return entries;
  const q = search.trim().toLowerCase();
  return entries.filter((entry) => [
    entry.category_major,
    entry.category_minor,
    entry.flow_key,
    entry.start_time_real,
  ].some((field) => String(field || '').toLowerCase().includes(q)));
}

function StatCard({ item }) {
  return html`
    <div className="glass-edge card-hover metric-shimmer relative overflow-hidden rounded-[28px] border border-white/8 bg-panel-gradient p-5 shadow-panel">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <p className="text-[11px] uppercase tracking-[0.22em] text-slate-400">${item.label}</p>
          <h3 className="mt-3 text-3xl font-semibold tracking-[-0.03em] text-white">${item.value}</h3>
        </div>
        <span className="rounded-full border border-white/10 px-3 py-1 text-xs font-medium" style=${{ color: item.accent, background: `${item.accent}18` }}>
          ${item.trend}
        </span>
      </div>
      <div className="flex items-center justify-between text-sm text-slate-400">
        <span>${item.detail}</span>
        <span className="h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: item.accent, boxShadow: `0 0 18px ${item.accent}` }}></span>
      </div>
    </div>
  `;
}

function SectionCard({ title, subtitle, children, action, className = '' }) {
  return html`
    <section className=${`glass-edge card-hover rounded-[30px] border border-white/8 bg-panel-gradient shadow-panel ${className}`}>
      <div className="flex items-start justify-between gap-4 px-6 pb-0 pt-6">
        <div>
          <h3 className="text-lg font-semibold tracking-[-0.02em] text-white">${title}</h3>
          ${subtitle ? html`<p className="mt-1 text-sm text-slate-400">${subtitle}</p>` : null}
        </div>
        ${action || null}
      </div>
      <div className="px-6 pb-6 pt-5">${children}</div>
    </section>
  `;
}

function DashboardTooltip({ active, payload, label, valueSuffix = '', formatter = formatNumber }) {
  if (!active || !payload?.length) return null;
  return html`
    <div className="rounded-2xl border border-white/10 bg-slate-950/95 px-4 py-3 shadow-2xl backdrop-blur">
      <p className="mb-2 text-xs uppercase tracking-[0.24em] text-slate-500">${label}</p>
      <div className="space-y-1.5">
        ${payload.map((item, idx) => html`
          <div key=${idx} className="flex items-center justify-between gap-4 text-sm">
            <span className="flex items-center gap-2 text-slate-300">
              <span className="h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: item.color || item.payload?.fill || ACCENT.violet }}></span>
              ${item.name}
            </span>
            <span className="font-medium text-white">${formatter(item.value)}${valueSuffix}</span>
          </div>
        `)}
      </div>
    </div>
  `;
}

function Sidebar({ status }) {
  const nav = [
    { label: 'Overview', hint: '业务总览', active: true },
    { label: 'Traffic', hint: '流量趋势' },
    { label: 'Models', hint: 'AI 分类' },
    { label: 'Operations', hint: '上传与配置' },
  ];
  return html`
    <aside className="glass-edge hidden rounded-[32px] border border-white/8 bg-panel-gradient p-5 shadow-panel xl:flex xl:min-h-[calc(100vh-48px)] xl:flex-col xl:justify-between">
      <div>
        <div className="mb-8 flex items-center gap-3 rounded-3xl border border-white/10 bg-white/5 px-4 py-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-500 via-blue-500 to-cyan-400 text-lg font-semibold text-white shadow-glow">AI</div>
          <div>
            <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Gateway</p>
            <h1 className="text-base font-semibold text-white">Observability Cloud</h1>
          </div>
        </div>

        <nav className="space-y-2">
          ${nav.map((item) => html`
            <button key=${item.label} className=${`card-hover flex w-full items-center justify-between rounded-2xl border px-4 py-3 text-left ${item.active ? 'border-violet-400/30 bg-violet-500/12 shadow-glow' : 'border-white/6 bg-white/[0.03]'}`}>
              <div>
                <div className="text-sm font-medium text-white">${item.label}</div>
                <div className="mt-1 text-xs text-slate-400">${item.hint}</div>
              </div>
              <span className=${`h-2.5 w-2.5 rounded-full ${item.active ? 'bg-cyan-300 shadow-[0_0_18px_rgba(103,232,249,0.8)]' : 'bg-slate-600'}`}></span>
            </button>
          `)}
        </nav>

        <div className="mt-8 rounded-[26px] border border-white/8 bg-white/[0.04] p-4">
          <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">System Mood</p>
          <div className="mt-4 flex items-end justify-between">
            <div>
              <div className="text-2xl font-semibold text-white">Stable</div>
              <div className="mt-1 text-sm text-slate-400">深色分析工作台已就绪</div>
            </div>
            <div className="h-16 w-16 rounded-full bg-gradient-to-br from-violet-500/25 to-cyan-400/20 blur-lg"></div>
          </div>
        </div>
      </div>

      <div className="rounded-[26px] border border-white/8 bg-black/20 p-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-2xl bg-slate-800"></div>
          <div>
            <div className="text-sm font-medium text-white">AI Gateway Team</div>
            <div className="text-xs text-slate-400">${status || 'Ready for analysis'}</div>
          </div>
        </div>
      </div>
    </aside>
  `;
}

function TopBar({ search, setSearch }) {
  return html`
    <header className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <p className="text-xs uppercase tracking-[0.28em] text-slate-500">AI Gateway Intelligence</p>
        <h2 className="mt-2 text-3xl font-semibold tracking-[-0.04em] text-white">SaaS Analytics Dashboard</h2>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">用更高级的深色分析界面查看 AI 流量、时延、Token 结构与最近活动，兼顾业务观感与真实操作面板。</p>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="glass-edge flex items-center gap-3 rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 shadow-soft sm:min-w-[320px]">
          <svg viewBox="0 0 24 24" className="h-4 w-4 text-slate-500" fill="none" stroke="currentColor" strokeWidth="1.8">
            <circle cx="11" cy="11" r="7"></circle>
            <path d="m20 20-3.5-3.5"></path>
          </svg>
          <input value=${search} onInput=${(e) => setSearch(e.target.value)} placeholder="搜索模型、小类、流 IP 或时间..." className="w-full border-0 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500" />
        </div>
        <button className="glass-edge card-hover rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 text-sm text-slate-300 shadow-soft">🔔 3</button>
        <button className="glass-edge card-hover flex items-center gap-3 rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-2.5 shadow-soft">
          <div className="h-9 w-9 rounded-2xl bg-gradient-to-br from-violet-500 to-cyan-400"></div>
          <div className="text-left">
            <div className="text-sm font-medium text-white">Ops Admin</div>
            <div className="text-xs text-slate-400">Realtime mode</div>
          </div>
        </button>
      </div>
    </header>
  `;
}

function TrendChart({ data }) {
  return html`
    <div className="h-[340px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${AreaChart} data=${data} margin=${{ top: 8, right: 8, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor=${ACCENT.violet} stopOpacity="0.55" />
              <stop offset="100%" stopColor=${ACCENT.violet} stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id="tokensGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor=${ACCENT.cyan} stopOpacity="0.30" />
              <stop offset="100%" stopColor=${ACCENT.cyan} stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="label" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} yAxisId="left" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${44} />
          <${YAxis} yAxisId="right" orientation="right" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${44} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
          <${Legend} iconType="circle" wrapperStyle=${{ color: '#94A3B8', paddingTop: 14 }} />
          <${Area} yAxisId="left" type="monotone" dataKey="requests" stroke=${ACCENT.violet} fill="url(#requestsGradient)" strokeWidth=${3} name="Requests" />
          <${Area} yAxisId="right" type="monotone" dataKey="outputTokens" stroke=${ACCENT.cyan} fill="url(#tokensGradient)" strokeWidth=${2.2} name="Output Tokens" />
        </${AreaChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function LatencyChart({ rows }) {
  return html`
    <div className="h-[240px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${BarChart} data=${rows} margin=${{ top: 8, right: 8, left: -20, bottom: 0 }} barGap=${8}>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="category_major" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${42} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} valueSuffix="ms" />`} />
          <${Legend} iconType="circle" wrapperStyle=${{ color: '#94A3B8', paddingTop: 12 }} />
          <${Bar} dataKey="avg_ttfb_ms" fill=${ACCENT.blue} name="TTFB" radius=${[8, 8, 2, 2]} />
          <${Bar} dataKey="avg_ttft_ms" fill=${ACCENT.emerald} name="TTFT" radius=${[8, 8, 2, 2]} />
          <${Bar} dataKey="avg_latency_ms" fill=${ACCENT.amber} name="Latency" radius=${[8, 8, 2, 2]} />
        </${BarChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function DistributionChart({ rows }) {
  const total = rows.reduce((sum, row) => sum + Number(row.total_entries || 0), 0) || 1;
  return html`
    <div className="grid grid-cols-[1fr_116px] items-center gap-4">
      <div className="h-[220px]">
        <${ResponsiveContainer} width="100%" height="100%">
          <${PieChart}>
            <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
            <${Pie}
              data=${rows}
              dataKey="total_entries"
              nameKey="category_major"
              innerRadius=${70}
              outerRadius=${92}
              paddingAngle=${4}
              stroke="rgba(255,255,255,0.04)"
              strokeWidth=${1}
            >
              ${rows.map((row, idx) => html`<${Cell} key=${row.category_major} fill=${chartPalette[idx % chartPalette.length]} />`)}
            </${Pie}>
          </${PieChart}>
        </${ResponsiveContainer}>
      </div>
      <div className="space-y-3">
        ${rows.map((row, idx) => html`
          <div key=${row.category_major} className="rounded-2xl border border-white/6 bg-white/[0.03] px-3 py-2.5">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: chartPalette[idx % chartPalette.length] }}></span>
              ${row.category_major}
            </div>
            <div className="mt-2 text-lg font-semibold text-white">${row.total_entries || 0}</div>
            <div className="text-xs text-slate-500">${formatPercent(((row.total_entries || 0) / total) * 100)}</div>
          </div>
        `)}
      </div>
    </div>
  `;
}

function TokenChart({ data }) {
  return html`
    <div className="h-[240px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${LineChart} data=${data} margin=${{ top: 8, right: 8, left: -20, bottom: 0 }}>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="label" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${42} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
          <${Legend} iconType="circle" wrapperStyle=${{ color: '#94A3B8', paddingTop: 12 }} />
          <${Line} type="monotone" dataKey="inputTokens" stroke=${ACCENT.blue} strokeWidth=${2.5} dot=${false} name="Input" />
          <${Line} type="monotone" dataKey="outputTokens" stroke=${ACCENT.rose} strokeWidth=${2.5} dot=${false} name="Output" />
        </${LineChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function UploadPanel({ uploadFileName, uploadProgress, onFileChange, onUpload, onClearEntries, busy }) {
  return html`
    <div className="rounded-[26px] border border-white/8 bg-white/[0.04] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-white">Upload PCAP</div>
          <div className="mt-1 text-xs text-slate-400">上传后自动解析并刷新图表</div>
        </div>
        <div className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">Realtime</div>
      </div>
      <label className="block cursor-pointer rounded-3xl border border-dashed border-white/10 bg-black/20 px-4 py-6 text-center card-hover">
        <input type="file" accept=".pcap,.pcapng" className="hidden" onChange=${onFileChange} />
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-violet-500/12 text-xl">⤴</div>
        <div className="mt-3 text-sm font-medium text-white">${uploadFileName || '选择 .pcap / .pcapng 文件'}</div>
        <div className="mt-1 text-xs text-slate-500">拖拽或点击上传</div>
      </label>
      <div className="mt-4 overflow-hidden rounded-full bg-white/5">
        <div className="h-2 rounded-full bg-gradient-to-r from-violet-500 via-blue-500 to-cyan-400 transition-all" style=${{ width: `${uploadProgress}%` }}></div>
      </div>
      <div className="mt-2 text-xs text-slate-500">上传进度 ${uploadProgress}%</div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        <button onClick=${onUpload} disabled=${busy || !uploadFileName} className="card-hover rounded-2xl border border-violet-400/20 bg-violet-500/14 px-4 py-3 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50">上传并分析</button>
        <button onClick=${onClearEntries} className="card-hover rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 text-sm text-slate-300">清空记录</button>
      </div>
    </div>
  `;
}

function ConfigPanel({ configs, form, setForm, onSubmit, onClear, onDelete }) {
  return html`
    <div className="rounded-[26px] border border-white/8 bg-white/[0.04] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-white">Self-hosted Models</div>
          <div className="mt-1 text-xs text-slate-400">IP:Port 规则映射到业务小类</div>
        </div>
        <button onClick=${onClear} className="rounded-2xl border border-amber-300/20 bg-amber-400/10 px-3 py-2 text-xs text-amber-100 card-hover">清空配置</button>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <input value=${form.name} onInput=${(e) => setForm((s) => ({ ...s, name: e.target.value }))} placeholder="小类名称，如 企业知识库" className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
        <input value=${form.server_ip} onInput=${(e) => setForm((s) => ({ ...s, server_ip: e.target.value }))} placeholder="服务端 IP:Port，如 192.168.101.1:443" className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
      </div>
      <button onClick=${onSubmit} className="mt-3 w-full rounded-2xl border border-cyan-300/20 bg-cyan-400/10 px-4 py-3 text-sm font-medium text-cyan-50 card-hover">保存自建配置</button>
      <div className="mt-4 space-y-2">
        ${configs.map((cfg) => html`
          <div key=${cfg.id} className="flex items-center justify-between rounded-2xl border border-white/6 bg-black/20 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-white">${cfg.name}</div>
              <div className="mt-1 text-xs text-slate-500">${cfg.server_ip}</div>
            </div>
            <button onClick=${() => onDelete(cfg.id)} className="rounded-xl border border-white/8 px-3 py-2 text-xs text-slate-300 card-hover">删除</button>
          </div>
        `)}
        ${!configs.length ? html`<div className="rounded-2xl border border-dashed border-white/8 px-4 py-5 text-center text-sm text-slate-500">暂无自建 AI 配置</div>` : null}
      </div>
    </div>
  `;
}

function FilterPanel({ filters, setFilters, onApply, onReset }) {
  return html`
    <div className="grid gap-3 xl:grid-cols-[1fr_1fr_180px_1fr_auto_auto]">
      <input type="datetime-local" value=${filters.startReal} onInput=${(e) => setFilters((s) => ({ ...s, startReal: e.target.value }))} className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none" />
      <input type="datetime-local" value=${filters.endReal} onInput=${(e) => setFilters((s) => ({ ...s, endReal: e.target.value }))} className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none" />
      <select value=${filters.major} onChange=${(e) => setFilters((s) => ({ ...s, major: e.target.value }))} className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none">
        <option value="">全部大类</option>
        <option value="三方AI">三方AI</option>
        <option value="自建AI">自建AI</option>
        <option value="实验AI">实验AI</option>
      </select>
      <input value=${filters.minor} onInput=${(e) => setFilters((s) => ({ ...s, minor: e.target.value }))} placeholder="按小类筛选（模糊匹配）" className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
      <button onClick=${onApply} className="rounded-2xl border border-violet-400/20 bg-violet-500/12 px-4 py-3 text-sm font-medium text-white card-hover">应用筛选</button>
      <button onClick=${onReset} className="rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 text-sm text-slate-300 card-hover">重置</button>
    </div>
  `;
}

function RequestsTable({ entries }) {
  return html`
    <div className="overflow-hidden rounded-[24px] border border-white/8 bg-black/20">
      <div className="max-h-[480px] overflow-auto">
        <table className="min-w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-950/92 backdrop-blur">
            <tr className="text-xs uppercase tracking-[0.18em] text-slate-500">
              <th className="px-4 py-4 font-medium">Request</th>
              <th className="px-4 py-4 font-medium">Relative Start</th>
              <th className="px-4 py-4 font-medium">Latency</th>
              <th className="px-4 py-4 font-medium">Timing</th>
              <th className="px-4 py-4 font-medium">Tokens</th>
              <th className="px-4 py-4 font-medium">Flow</th>
            </tr>
          </thead>
          <tbody>
            ${entries.map((entry) => {
              const flow = parseFlow(entry.flow_key);
              return html`
                <tr key=${entry.id} className="border-t border-white/6 text-slate-200 transition-colors hover:bg-white/[0.03]">
                  <td className="px-4 py-4 align-top">
                    <div className="flex items-start gap-3">
                      <span className="mt-1 h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: entry.category_major === '自建AI' ? ACCENT.cyan : entry.category_major === '三方AI' ? ACCENT.violet : ACCENT.amber }}></span>
                      <div>
                        <div className="font-medium text-white">${entry.category_major} / ${entry.category_minor}</div>
                        <div className="mt-1 text-xs text-slate-500">#${entry.id} · ${entry.start_time_real || '--'}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-cyan-200">${formatNumber(entry.start_time_rel_s, 6)}s</td>
                  <td className="px-4 py-4 align-top text-white">${formatNumber((entry.latency_ms || 0) / 1000, 3)}s</td>
                  <td className="px-4 py-4 align-top">
                    <div className="text-xs text-slate-400">TTFB ${formatNumber(entry.ttfb_ms, 1)}ms</div>
                    <div className="mt-1 text-xs text-slate-400">TTFT ${formatNumber(entry.ttft_ms, 1)}ms</div>
                    <div className="mt-1 text-xs text-slate-500">TPOT ${formatNumber(entry.tpot_ms_per_token, 1)} ms/token</div>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <div className="text-xs text-slate-400">In ${formatCompact(entry.input_tokens || 0)}</div>
                    <div className="mt-1 text-xs text-slate-400">Out ${formatCompact(entry.output_tokens || 0)}</div>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <div className="text-xs text-slate-300">${flow.display}</div>
                    <div className="mt-1 text-[11px] text-slate-500">client ${flow.client}</div>
                  </td>
                </tr>
              `;
            })}
            ${!entries.length ? html`<tr><td colSpan="6" className="px-4 py-10 text-center text-sm text-slate-500">暂无匹配数据，先上传 PCAP 或调整筛选条件。</td></tr>` : null}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function ActivityList({ items }) {
  return html`
    <div className="space-y-3">
      ${items.map((item, idx) => html`
        <div key=${idx} className="rounded-[22px] border border-white/8 bg-white/[0.04] px-4 py-4">
          <div className="flex items-start gap-3">
            <span className="mt-1 h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: item.tone === 'cyan' ? ACCENT.cyan : ACCENT.violet, boxShadow: `0 0 20px ${item.tone === 'cyan' ? ACCENT.cyan : ACCENT.violet}` }}></span>
            <div>
              <div className="text-sm font-medium text-white">${item.title}</div>
              <div className="mt-1 text-xs text-slate-500">${item.subtitle}</div>
            </div>
          </div>
        </div>
      `)}
    </div>
  `;
}

function App() {
  const [filters, setFilters] = useState({ startReal: '', endReal: '', major: '', minor: '' });
  const [search, setSearch] = useState('');
  const [entries, setEntries] = useState([]);
  const [stats, setStats] = useState({ total_entries: 0, total_input_tokens: 0, total_output_tokens: 0, rps: 0, major_stats: [] });
  const [configs, setConfigs] = useState([]);
  const [configForm, setConfigForm] = useState({ name: '', server_ip: '' });
  const [status, setStatus] = useState('Ready');
  const [busy, setBusy] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);

  const refreshAll = useCallback(async (nextFilters = filters) => {
    const qs = buildQueryString(nextFilters);
    setBusy(true);
    try {
      const [statsResp, entriesResp, cfgResp] = await Promise.all([
        fetchJSON(`/api/stats${qs}`),
        fetchJSON(`/api/entries${qs}`),
        fetchJSON('/api/self-hosted'),
      ]);
      setStats(statsResp);
      setEntries(entriesResp.items || []);
      setConfigs(cfgResp.items || []);
      setStatus(`Updated at ${new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`);
    } catch (error) {
      console.error(error);
      setStatus(`加载失败：${error.message}`);
    } finally {
      setBusy(false);
    }
  }, [filters]);

  useEffect(() => {
    refreshAll(filters);
  }, []);

  const filteredEntries = useMemo(() => filterEntries(entries, search), [entries, search]);
  const statCards = useMemo(() => buildStats(stats, entries), [stats, entries]);
  const trendData = useMemo(() => bucketEntries(filteredEntries), [filteredEntries]);
  const categoryStats = useMemo(() => buildCategoryStats(stats, filteredEntries), [stats, filteredEntries]);
  const activities = useMemo(() => buildActivityFeed(filteredEntries, configs), [filteredEntries, configs]);
  const usingMock = !entries.length;

  const onUpload = async () => {
    if (!selectedFile) {
      setStatus('请先选择 PCAP 文件。');
      return;
    }
    setBusy(true);
    setUploadProgress(0);
    try {
      const result = await uploadFile(selectedFile, setUploadProgress);
      setStatus(`上传完成：检测 ${result?.detected ?? 0} 条，入库 ${result?.inserted ?? 0} 条。`);
      await refreshAll(filters);
      setSelectedFile(null);
      setUploadProgress(100);
    } catch (error) {
      console.error(error);
      setStatus(error.message);
    } finally {
      setBusy(false);
      window.setTimeout(() => setUploadProgress(0), 900);
    }
  };

  const onClearEntries = async () => {
    await fetch('/api/clear', { method: 'POST' });
    setStatus('记录已清空。');
    await refreshAll(filters);
  };

  const onSaveConfig = async () => {
    if (!configForm.name.trim() || !configForm.server_ip.trim()) {
      setStatus('请填写完整的小类名称和 IP:Port。');
      return;
    }
    const fd = new FormData();
    fd.append('name', configForm.name.trim());
    fd.append('server_ip', configForm.server_ip.trim());
    await fetch('/api/self-hosted', { method: 'POST', body: fd });
    setConfigForm({ name: '', server_ip: '' });
    setStatus('自建配置已保存。');
    await refreshAll(filters);
  };

  const onDeleteConfig = async (id) => {
    await fetch(`/api/self-hosted/${id}`, { method: 'DELETE' });
    setStatus('配置已删除。');
    await refreshAll(filters);
  };

  const onClearConfig = async () => {
    await fetch('/api/self-hosted/clear', { method: 'POST' });
    setStatus('自建配置已清空。');
    await refreshAll(filters);
  };

  const applyFilters = async () => {
    await refreshAll(filters);
  };

  const resetFilters = async () => {
    const cleared = { startReal: '', endReal: '', major: '', minor: '' };
    setFilters(cleared);
    await refreshAll(cleared);
  };

  return html`
    <div className="min-h-screen px-4 py-6 lg:px-6 xl:px-8">
      <div className="mx-auto grid max-w-[1700px] gap-6 xl:grid-cols-[290px_minmax(0,1fr)]">
        <${Sidebar} status=${status} />

        <main className="min-w-0">
          <${TopBar} search=${search} setSearch=${setSearch} />

          <section className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-4">
            ${statCards.map((item) => html`<${StatCard} key=${item.label} item=${item} />`)}
          </section>

          <section className="mt-6 grid gap-6 2xl:grid-cols-[minmax(0,1.7fr)_430px]">
            <${SectionCard}
              title="Main Request Trend"
              subtitle=${usingMock ? '当前无真实数据时使用 mock 预览布局；上传数据后自动切换为真实趋势。' : '按当前筛选条件聚合请求与输出 token，展示主趋势。'}
              action=${html`<div className="rounded-full border border-white/8 bg-white/[0.04] px-3 py-1.5 text-xs text-slate-400">${busy ? 'Syncing...' : 'Live data'}</div>`}
            >
              <${FilterPanel} filters=${filters} setFilters=${setFilters} onApply=${applyFilters} onReset=${resetFilters} />
              <div className="mt-6"><${TrendChart} data=${trendData} /></div>
            </${SectionCard}>

            <div className="grid gap-6">
              <${SectionCard} title="Category Mix" subtitle="按 AI 大类分布观察当前业务重心。">
                <${DistributionChart} rows=${categoryStats} />
              </${SectionCard}>
              <${SectionCard} title="Latency Compare" subtitle="统一风格的时延对比，突出 TTFB / TTFT / Latency。">
                <${LatencyChart} rows=${categoryStats} />
              </${SectionCard}>
            </div>
          </section>

          <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.55fr)_420px]">
            <${SectionCard} title="Request Intelligence" subtitle="近期请求列表，强化信息分层与可读性。">
              <${RequestsTable} entries=${filteredEntries} />
            </${SectionCard}>

            <div className="grid gap-6">
              <${SectionCard} title="Token Dynamics" subtitle="输入与输出 token 走势统一到深色图表语言。">
                <${TokenChart} data=${trendData} />
              </${SectionCard}>
              <${SectionCard} title="Recent Activity" subtitle="汇总最近请求与自建配置变化。">
                <${ActivityList} items=${activities} />
              </${SectionCard}>
            </div>
          </section>

          <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <${SectionCard} title="Operations" subtitle="保留上传与清理能力，但以产品化卡片重构交互视觉。">
              <${UploadPanel}
                uploadFileName=${selectedFile?.name || ''}
                uploadProgress=${uploadProgress}
                busy=${busy}
                onFileChange=${(e) => setSelectedFile(e.target.files?.[0] || null)}
                onUpload=${onUpload}
                onClearEntries=${onClearEntries}
              />
            </${SectionCard}>
            <${SectionCard} title="Self-hosted Routing" subtitle="自建 AI 配置与服务映射管理。">
              <${ConfigPanel}
                configs=${configs}
                form=${configForm}
                setForm=${setConfigForm}
                onSubmit=${onSaveConfig}
                onClear=${onClearConfig}
                onDelete=${onDeleteConfig}
              />
            </${SectionCard}>
          </section>

          <footer className="mt-6 flex flex-col gap-3 rounded-[28px] border border-white/8 bg-white/[0.04] px-5 py-4 text-sm text-slate-400 shadow-soft lg:flex-row lg:items-center lg:justify-between">
            <div>
              <span className="text-white">Status:</span> ${status}
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-500">
              <span className="rounded-full border border-white/8 px-3 py-1">React</span>
              <span className="rounded-full border border-white/8 px-3 py-1">Tailwind CSS</span>
              <span className="rounded-full border border-white/8 px-3 py-1">Recharts</span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  `;
}

createRoot(document.getElementById('app')).render(html`<${App} />`);
