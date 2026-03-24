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
} from 'https://esm.sh/recharts@2.12.7';

const html = htm.bind(React.createElement);

const ACCENT = {
  primary: '#9B8CFF',
  secondary: '#59D0FF',
  mint: '#56F0C5',
  rose: '#FF7AA2',
  amber: '#FFC56C',
  text: '#E6EBFF',
  muted: '#8B96BC',
  line: 'rgba(255,255,255,0.08)',
  panel: '#0D1324',
  panelSoft: '#111A31',
};

const CHART_COLORS = [ACCENT.primary, ACCENT.secondary, ACCENT.mint, ACCENT.rose, ACCENT.amber];

const mockEntries = [
  {
    id: 'demo-1',
    start_time_real: '2026-03-19 09:12:14',
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
    start_time_real: '2026-03-19 09:16:41',
    start_time_rel_s: 266.102834,
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
    start_time_real: '2026-03-19 09:24:05',
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
  {
    id: 'demo-4',
    start_time_real: '2026-03-19 09:29:51',
    start_time_rel_s: 1051.201205,
    latency_ms: 2120.2,
    category_major: '自建AI',
    category_minor: 'RAG 工作台',
    flow_key: '10.10.8.12:55321-192.168.101.7:9443',
    ttfb_ms: 288.4,
    ttft_ms: 603.1,
    tpot_ms_per_token: 24.7,
    input_tokens: 1115,
    output_tokens: 196,
  },
];

const mockConfigs = [
  { id: 1, name: '知识助手', server_ip: '192.168.101.1:8443' },
  { id: 2, name: 'RAG 工作台', server_ip: '192.168.101.7:9443' },
  { id: 3, name: '内部 Copilot', server_ip: '172.16.30.9:8080' },
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
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
  return resp.json();
}

function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.responseType = 'json';
    xhr.upload.onprogress = (evt) => {
      if (evt.lengthComputable) onProgress(Math.min(100, Math.round((evt.loaded / evt.total) * 100)));
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response);
      else reject(new Error(`上传失败：${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error('上传失败：网络异常'));
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

function sourceEntries(entries) {
  return entries.length ? entries : mockEntries;
}

function sourceStats(stats, entries) {
  return entries.length ? stats : mockStats;
}

function sourceConfigs(configs) {
  return configs.length ? configs : mockConfigs;
}

function bucketEntries(entries) {
  const source = sourceEntries(entries);
  const buckets = new Map();
  source.forEach((entry, index) => {
    const label = entry.start_time_real ? entry.start_time_real.slice(11, 16) : `#${index + 1}`;
    const current = buckets.get(label) || { label, requests: 0, inputTokens: 0, outputTokens: 0, latencySum: 0, ttfbSum: 0 };
    current.requests += 1;
    current.inputTokens += Number(entry.input_tokens || 0);
    current.outputTokens += Number(entry.output_tokens || 0);
    current.latencySum += Number(entry.latency_ms || 0) / 1000;
    current.ttfbSum += Number(entry.ttfb_ms || 0);
    buckets.set(label, current);
  });
  return Array.from(buckets.values()).map((item) => ({
    label: item.label,
    requests: item.requests,
    inputTokens: item.inputTokens,
    outputTokens: item.outputTokens,
    latency: Number((item.latencySum / item.requests).toFixed(2)),
    ttfb: Number((item.ttfbSum / item.requests).toFixed(1)),
  }));
}

function buildCategoryStats(stats, entries) {
  const rows = sourceStats(stats, entries).major_stats || [];
  return rows.length ? rows : mockStats.major_stats;
}

function buildActivityFeed(entries, configs) {
  const liveEntries = sourceEntries(entries);
  const liveConfigs = sourceConfigs(configs);
  const entryItems = liveEntries.slice(0, 4).map((entry, idx) => ({
    title: `${entry.category_major} / ${entry.category_minor}`,
    subtitle: `${entry.start_time_real || '刚刚'} · ${formatNumber((entry.latency_ms || 0) / 1000, 2)}s latency`,
    tone: idx % 2 === 0 ? ACCENT.primary : ACCENT.secondary,
  }));
  const cfgItems = liveConfigs.slice(0, 2).map((cfg) => ({
    title: `自建路由映射：${cfg.name}`,
    subtitle: cfg.server_ip,
    tone: ACCENT.mint,
  }));
  return [...entryItems, ...cfgItems];
}

function buildPerformanceSummary(entries, stats) {
  const liveEntries = sourceEntries(entries);
  const source = sourceStats(stats, entries);
  const avgLatency = liveEntries.reduce((sum, item) => sum + Number(item.latency_ms || 0), 0) / liveEntries.length / 1000;
  const avgTtft = liveEntries.reduce((sum, item) => sum + Number(item.ttft_ms || 0), 0) / liveEntries.length;
  const avgOutput = liveEntries.reduce((sum, item) => sum + Number(item.output_tokens || 0), 0) / liveEntries.length;
  const dominant = (source.major_stats || []).slice().sort((a, b) => (b.total_entries || 0) - (a.total_entries || 0))[0] || mockStats.major_stats[0];
  return {
    avgLatency,
    avgTtft,
    avgOutput,
    dominant,
    totalRequests: source.total_entries || 0,
    inputTokens: source.total_input_tokens || 0,
    outputTokens: source.total_output_tokens || 0,
    rps: source.rps || 0,
  };
}

function buildHealthRows(entries) {
  const liveEntries = sourceEntries(entries);
  const byMinor = new Map();
  liveEntries.forEach((entry) => {
    const key = entry.category_minor || '未知';
    const row = byMinor.get(key) || { label: key, requests: 0, latencySum: 0, output: 0, major: entry.category_major };
    row.requests += 1;
    row.latencySum += Number(entry.latency_ms || 0);
    row.output += Number(entry.output_tokens || 0);
    byMinor.set(key, row);
  });
  return Array.from(byMinor.values())
    .map((row) => ({
      ...row,
      latency: row.latencySum / row.requests,
      score: Math.max(42, Math.min(98, 100 - (row.latencySum / row.requests) / 80 + row.output / 18)),
    }))
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 5);
}

function buildMetricCards(entries, stats) {
  const summary = buildPerformanceSummary(entries, stats);
  return [
    {
      label: 'Total Requests',
      value: formatCompact(summary.totalRequests),
      meta: `${summary.totalRequests} captured requests`,
      tone: ACCENT.primary,
      delta: '+18.4%',
    },
    {
      label: 'Prompt Tokens',
      value: formatCompact(summary.inputTokens),
      meta: `Output ${formatCompact(summary.outputTokens)}`,
      tone: ACCENT.secondary,
      delta: '+9.8%',
    },
    {
      label: 'Avg TTFT',
      value: `${formatNumber(summary.avgTtft, 1)}ms`,
      meta: `Latency ${formatNumber(summary.avgLatency, 2)}s`,
      tone: ACCENT.mint,
      delta: '-4.2%',
    },
    {
      label: 'Realtime RPS',
      value: formatNumber(summary.rps, 1),
      meta: `Top segment ${summary.dominant.category_major}`,
      tone: ACCENT.amber,
      delta: '+1.7%',
    },
  ];
}

function buildTopFlows(entries) {
  return sourceEntries(entries)
    .slice()
    .sort((a, b) => Number(b.output_tokens || 0) - Number(a.output_tokens || 0))
    .slice(0, 5)
    .map((entry) => ({
      id: entry.id,
      label: `${entry.category_major} / ${entry.category_minor}`,
      flow: parseFlow(entry.flow_key).server,
      output: Number(entry.output_tokens || 0),
      latency: Number(entry.latency_ms || 0) / 1000,
    }));
}

function filterEntries(entries, search) {
  if (!search.trim()) return entries;
  const q = search.trim().toLowerCase();
  return entries.filter((entry) => [entry.category_major, entry.category_minor, entry.flow_key, entry.start_time_real]
    .some((field) => String(field || '').toLowerCase().includes(q)));
}

function icon(color) {
  return html`<span className="inline-flex h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: color, boxShadow: `0 0 20px ${color}` }}></span>`;
}

function Panel({ title, subtitle, action, children, className = '' }) {
  return html`
    <section className=${`glass-edge premium-panel premium-shadow rounded-[34px] border border-white/8 bg-panel-gradient ${className}`}>
      <div className="flex items-start justify-between gap-4 px-6 pb-0 pt-6">
        <div>
          <div className="text-[11px] uppercase tracking-[0.26em] text-slate-500">Analytics</div>
          <h3 className="mt-2 text-[22px] font-semibold tracking-[-0.03em] text-white">${title}</h3>
          ${subtitle ? html`<p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">${subtitle}</p>` : null}
        </div>
        ${action || null}
      </div>
      <div className="px-6 pb-6 pt-5">${children}</div>
    </section>
  `;
}

function DashboardTooltip({ active, payload, label, suffix = '' }) {
  if (!active || !payload?.length) return null;
  return html`
    <div className="rounded-[20px] border border-white/10 bg-slate-950/95 px-4 py-3 shadow-2xl backdrop-blur-md">
      <div className="mb-2 text-[11px] uppercase tracking-[0.24em] text-slate-500">${label}</div>
      <div className="space-y-1.5">
        ${payload.map((item, idx) => html`
          <div key=${idx} className="flex items-center justify-between gap-4 text-sm">
            <span className="flex items-center gap-2 text-slate-300">
              <span className="h-2.5 w-2.5 rounded-full" style=${{ backgroundColor: item.color || ACCENT.primary }}></span>
              ${item.name}
            </span>
            <span className="font-medium text-white">${formatNumber(item.value, 1)}${suffix}</span>
          </div>
        `)}
      </div>
    </div>
  `;
}

function Sidebar({ status }) {
  const nav = [
    ['Overview', true],
    ['Traffic', false],
    ['Models', false],
    ['Routing', false],
  ];
  return html`
    <aside className="glass-edge premium-panel premium-shadow hidden min-h-[calc(100vh-42px)] rounded-[36px] border border-white/8 bg-panel-gradient xl:flex xl:flex-col xl:justify-between xl:p-5">
      <div>
        <div className="rounded-[28px] border border-white/10 bg-white/[0.04] p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-14 w-14 items-center justify-center rounded-[22px] bg-[radial-gradient(circle_at_30%_20%,rgba(155,140,255,.85),rgba(89,208,255,.65)_55%,rgba(86,240,197,.55))] text-lg font-semibold text-white shadow-[0_12px_40px_rgba(103,88,255,.35)]">AI</div>
            <div>
              <div className="text-[11px] uppercase tracking-[0.26em] text-slate-500">Gateway Suite</div>
              <div className="mt-1 text-base font-semibold text-white">Pulse Analytics</div>
            </div>
          </div>
        </div>

        <div className="mt-6 space-y-2">
          ${nav.map(([label, active]) => html`
            <button key=${label} className=${`nav-pill flex w-full items-center justify-between rounded-[22px] border px-4 py-3 ${active ? 'border-violet-300/25 bg-violet-400/10 text-white' : 'border-white/6 bg-white/[0.03] text-slate-300'}`}>
              <span className="text-sm font-medium">${label}</span>
              ${icon(active ? ACCENT.secondary : '#475569')}
            </button>
          `)}
        </div>

        <div className="mt-8 rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02))] p-4">
          <div className="text-[11px] uppercase tracking-[0.26em] text-slate-500">Command</div>
          <div className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">Observability</div>
          <p className="mt-2 text-sm leading-6 text-slate-400">A premium dashboard surface for request timing, token economics, and model routing performance.</p>
          <div className="mt-5 flex items-center gap-3 text-xs text-slate-400">
            ${icon(ACCENT.mint)}<span>${status || 'Live sync ready'}</span>
          </div>
        </div>
      </div>

      <div className="rounded-[28px] border border-white/8 bg-black/20 p-4">
        <div className="text-[11px] uppercase tracking-[0.26em] text-slate-500">Workspace</div>
        <div className="mt-3 flex items-center gap-3">
          <div className="h-11 w-11 rounded-[18px] bg-gradient-to-br from-violet-500 to-cyan-400"></div>
          <div>
            <div className="text-sm font-medium text-white">Ops Admin</div>
            <div className="text-xs text-slate-500">AI Gateway Control Plane</div>
          </div>
        </div>
      </div>
    </aside>
  `;
}

function TopBar({ search, setSearch, status }) {
  return html`
    <header className="mb-6 flex flex-col gap-4 2xl:flex-row 2xl:items-center 2xl:justify-between">
      <div>
        <div className="text-[11px] uppercase tracking-[0.28em] text-slate-500">Behance-inspired data clarity</div>
        <h1 className="mt-3 max-w-4xl text-4xl font-semibold tracking-[-0.05em] text-white md:text-[48px]">AI Gateway analytics, redesigned as a premium dark SaaS command center.</h1>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-400">强调更强的层次、克制高亮、信息密度与图表气质；让它更像设计作品集里的成品，而不是普通后台模板。</p>
      </div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="glass-edge flex items-center gap-3 rounded-[24px] border border-white/8 bg-white/[0.05] px-4 py-3.5 min-w-[300px] premium-shadow">
          <svg viewBox="0 0 24 24" className="h-4 w-4 text-slate-500" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>
          <input value=${search} onInput=${(e) => setSearch(e.target.value)} placeholder="搜索模型、小类、流 IP、时间..." className="w-full border-0 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500" />
        </div>
        <div className="flex items-center gap-3">
          <button className="glass-edge premium-shadow rounded-[22px] border border-white/8 bg-white/[0.05] px-4 py-3 text-sm text-slate-300">🔔</button>
          <div className="glass-edge premium-shadow flex items-center gap-3 rounded-[22px] border border-white/8 bg-white/[0.05] px-4 py-2.5">
            <div className="h-10 w-10 rounded-[18px] bg-gradient-to-br from-violet-500 to-cyan-400"></div>
            <div>
              <div className="text-sm font-medium text-white">System Sync</div>
              <div className="text-xs text-slate-500">${status || 'Ready'}</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  `;
}

function MetricCard({ item }) {
  return html`
    <div className="glass-edge premium-panel metric-sheen rounded-[30px] border border-white/8 bg-panel-gradient p-5 premium-shadow">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">${item.label}</div>
          <div className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-white">${item.value}</div>
        </div>
        <div className="rounded-full border border-white/10 px-3 py-1 text-xs font-medium" style=${{ color: item.tone, background: `${item.tone}14` }}>${item.delta}</div>
      </div>
      <div className="mt-6 flex items-center justify-between gap-3">
        <div className="text-sm text-slate-400">${item.meta}</div>
        ${icon(item.tone)}
      </div>
    </div>
  `;
}

function HeroSpotlight({ summary, trendData, usingMock }) {
  const heroSpark = trendData.slice(-7);
  return html`
    <section className="glass-edge hero-panel premium-shadow overflow-hidden rounded-[36px] border border-white/8 bg-panel-gradient p-6">
      <div className="absolute right-[-80px] top-[-60px] h-[220px] w-[220px] rounded-full bg-violet-500/18 blur-3xl"></div>
      <div className="absolute bottom-[-100px] right-[20%] h-[240px] w-[240px] rounded-full bg-cyan-400/10 blur-3xl"></div>
      <div className="relative grid gap-6 xl:grid-cols-[minmax(0,1.25fr)_360px] xl:items-end">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.05] px-3 py-1.5 text-xs text-slate-300">
            ${icon(ACCENT.mint)}<span>${usingMock ? 'Demo preview mode' : 'Live production metrics'}</span>
          </div>
          <h2 className="mt-5 max-w-3xl text-[34px] font-semibold leading-tight tracking-[-0.05em] text-white md:text-[42px]">Data clarity first, visual storytelling second — both polished to feel like a real premium SaaS product.</h2>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-400">参考高质量 SaaS analytics dashboard 的排版逻辑：大标题建立情绪，主趋势图承担中心叙事，侧边补充卡片负责细分洞察与可操作性。</p>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <div className="rounded-[24px] border border-white/8 bg-white/[0.05] p-4">
              <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Dominant Segment</div>
              <div className="mt-3 text-2xl font-semibold text-white">${summary.dominant.category_major}</div>
              <div className="mt-2 text-sm text-slate-400">${summary.dominant.total_entries} requests in focus</div>
            </div>
            <div className="rounded-[24px] border border-white/8 bg-white/[0.05] p-4">
              <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Avg Output</div>
              <div className="mt-3 text-2xl font-semibold text-white">${formatNumber(summary.avgOutput, 0)}</div>
              <div className="mt-2 text-sm text-slate-400">tokens / request</div>
            </div>
            <div className="rounded-[24px] border border-white/8 bg-white/[0.05] p-4">
              <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Health Pulse</div>
              <div className="mt-3 text-2xl font-semibold text-white">${formatPercent(Math.min(99.6, 94 + summary.rps / 10))}</div>
              <div className="mt-2 text-sm text-slate-400">steady response quality</div>
            </div>
          </div>
        </div>
        <div className="rounded-[30px] border border-white/8 bg-black/20 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Executive Pulse</div>
              <div className="mt-2 text-lg font-semibold text-white">Realtime throughput</div>
            </div>
            <div className="rounded-full border border-cyan-300/15 bg-cyan-300/10 px-3 py-1 text-xs text-cyan-100">${formatNumber(summary.rps, 1)} RPS</div>
          </div>
          <div className="mt-6 h-[160px]">
            <${ResponsiveContainer} width="100%" height="100%">
              <${AreaChart} data=${heroSpark} margin=${{ top: 8, right: 0, left: -24, bottom: 0 }}>
                <defs>
                  <linearGradient id="heroGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor=${ACCENT.secondary} stopOpacity="0.55" />
                    <stop offset="100%" stopColor=${ACCENT.secondary} stopOpacity="0.02" />
                  </linearGradient>
                </defs>
                <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
                <${XAxis} dataKey="label" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
                <${YAxis} hide=${true} />
                <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
                <${Area} type="monotone" dataKey="requests" stroke=${ACCENT.secondary} fill="url(#heroGradient)" strokeWidth=${3} name="Requests" />
              </${AreaChart}>
            </${ResponsiveContainer}>
          </div>
          <div className="mt-5 grid grid-cols-2 gap-3">
            <div className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
              <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Avg Latency</div>
              <div className="mt-2 text-2xl font-semibold text-white">${formatNumber(summary.avgLatency, 2)}s</div>
            </div>
            <div className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
              <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Avg TTFT</div>
              <div className="mt-2 text-2xl font-semibold text-white">${formatNumber(summary.avgTtft, 1)}ms</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  `;
}

function MainTrendChart({ data }) {
  return html`
    <div className="h-[340px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${AreaChart} data=${data} margin=${{ top: 12, right: 6, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="mainTrendReq" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor=${ACCENT.primary} stopOpacity="0.62" />
              <stop offset="100%" stopColor=${ACCENT.primary} stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id="mainTrendOut" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor=${ACCENT.mint} stopOpacity="0.25" />
              <stop offset="100%" stopColor=${ACCENT.mint} stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="label" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} yAxisId="left" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${40} />
          <${YAxis} yAxisId="right" orientation="right" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${40} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
          <${Area} yAxisId="left" type="monotone" dataKey="requests" stroke=${ACCENT.primary} fill="url(#mainTrendReq)" strokeWidth=${3} name="Requests" />
          <${Area} yAxisId="right" type="monotone" dataKey="outputTokens" stroke=${ACCENT.mint} fill="url(#mainTrendOut)" strokeWidth=${2.2} name="Output Tokens" />
        </${AreaChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function DistributionChart({ rows }) {
  const total = rows.reduce((sum, row) => sum + Number(row.total_entries || 0), 0) || 1;
  return html`
    <div className="grid gap-4 xl:grid-cols-[180px_1fr] xl:items-center">
      <div className="h-[190px]">
        <${ResponsiveContainer} width="100%" height="100%">
          <${PieChart}>
            <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
            <${Pie} data=${rows} dataKey="total_entries" nameKey="category_major" innerRadius=${58} outerRadius=${82} paddingAngle=${4} stroke="rgba(255,255,255,0.04)">
              ${rows.map((row, idx) => html`<${Cell} key=${row.category_major} fill=${CHART_COLORS[idx % CHART_COLORS.length]} />`)}
            </${Pie}>
          </${PieChart}>
        </${ResponsiveContainer}>
      </div>
      <div className="space-y-3">
        ${rows.map((row, idx) => html`
          <div key=${row.category_major} className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm text-white">${icon(CHART_COLORS[idx % CHART_COLORS.length])}<span>${row.category_major}</span></div>
              <div className="text-sm font-medium text-white">${formatPercent((row.total_entries / total) * 100)}</div>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/6">
              <div className="h-full rounded-full" style=${{ width: `${(row.total_entries / total) * 100}%`, background: CHART_COLORS[idx % CHART_COLORS.length] }}></div>
            </div>
            <div className="mt-2 text-xs text-slate-500">${row.total_entries} requests</div>
          </div>
        `)}
      </div>
    </div>
  `;
}

function LatencyChart({ rows }) {
  return html`
    <div className="h-[260px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${BarChart} data=${rows} margin=${{ top: 12, right: 6, left: -20, bottom: 0 }} barGap=${10}>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="category_major" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${42} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} suffix="ms" />`} />
          <${Bar} dataKey="avg_ttfb_ms" fill=${ACCENT.secondary} radius=${[10, 10, 2, 2]} name="TTFB" />
          <${Bar} dataKey="avg_ttft_ms" fill=${ACCENT.mint} radius=${[10, 10, 2, 2]} name="TTFT" />
          <${Bar} dataKey="avg_latency_ms" fill=${ACCENT.amber} radius=${[10, 10, 2, 2]} name="Latency" />
        </${BarChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function TokenChart({ data }) {
  return html`
    <div className="h-[260px]">
      <${ResponsiveContainer} width="100%" height="100%">
        <${LineChart} data=${data} margin=${{ top: 12, right: 6, left: -20, bottom: 0 }}>
          <${CartesianGrid} vertical=${false} strokeDasharray="3 3" />
          <${XAxis} dataKey="label" tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} />
          <${YAxis} tickLine=${false} axisLine=${false} tick=${{ fill: '#64748B', fontSize: 12 }} width=${42} />
          <${Tooltip} content=${(props) => html`<${DashboardTooltip} ...${props} />`} />
          <${Line} type="monotone" dataKey="inputTokens" stroke=${ACCENT.secondary} strokeWidth=${2.6} dot=${false} name="Input" />
          <${Line} type="monotone" dataKey="outputTokens" stroke=${ACCENT.rose} strokeWidth=${2.6} dot=${false} name="Output" />
        </${LineChart}>
      </${ResponsiveContainer}>
    </div>
  `;
}

function FilterBar({ filters, setFilters, onApply, onReset }) {
  return html`
    <div className="grid gap-3 xl:grid-cols-[1fr_1fr_170px_1fr_auto_auto]">
      <input type="datetime-local" value=${filters.startReal} onInput=${(e) => setFilters((s) => ({ ...s, startReal: e.target.value }))} className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none" />
      <input type="datetime-local" value=${filters.endReal} onInput=${(e) => setFilters((s) => ({ ...s, endReal: e.target.value }))} className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none" />
      <select value=${filters.major} onChange=${(e) => setFilters((s) => ({ ...s, major: e.target.value }))} className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none">
        <option value="">全部大类</option>
        <option value="三方AI">三方AI</option>
        <option value="自建AI">自建AI</option>
        <option value="实验AI">实验AI</option>
      </select>
      <input value=${filters.minor} onInput=${(e) => setFilters((s) => ({ ...s, minor: e.target.value }))} placeholder="按小类筛选（模糊匹配）" className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
      <button onClick=${onApply} className="rounded-[20px] border border-violet-300/20 bg-violet-400/12 px-4 py-3 text-sm font-medium text-white">应用</button>
      <button onClick=${onReset} className="rounded-[20px] border border-white/8 bg-white/[0.04] px-4 py-3 text-sm text-slate-300">重置</button>
    </div>
  `;
}

function HealthList({ rows }) {
  return html`
    <div className="space-y-3">
      ${rows.map((row, idx) => html`
        <div key=${row.label} className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-white">${icon(CHART_COLORS[idx % CHART_COLORS.length])}<span>${row.label}</span></div>
              <div className="mt-1 text-xs text-slate-500">${row.major} · ${row.requests} requests</div>
            </div>
            <div className="text-right">
              <div className="text-sm font-medium text-white">${formatPercent(row.score)}</div>
              <div className="text-xs text-slate-500">service score</div>
            </div>
          </div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/6">
            <div className="h-full rounded-full" style=${{ width: `${row.score}%`, background: CHART_COLORS[idx % CHART_COLORS.length] }}></div>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
            <span>${formatNumber(row.latency / 1000, 2)}s avg latency</span>
            <span>${formatCompact(row.output)} output tokens</span>
          </div>
        </div>
      `)}
    </div>
  `;
}

function TopFlows({ flows }) {
  return html`
    <div className="space-y-3">
      ${flows.map((flow, idx) => html`
        <div key=${flow.id} className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-white">${icon(CHART_COLORS[idx % CHART_COLORS.length])}<span>${flow.label}</span></div>
              <div className="mt-1 text-xs text-slate-500">${flow.flow}</div>
            </div>
            <div className="text-right">
              <div className="text-sm font-medium text-white">${formatCompact(flow.output)}</div>
              <div className="text-xs text-slate-500">output</div>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
            <span>Request #${flow.id}</span>
            <span>${formatNumber(flow.latency, 2)}s latency</span>
          </div>
        </div>
      `)}
    </div>
  `;
}

function RequestsTable({ entries }) {
  return html`
    <div className="overflow-hidden rounded-[26px] border border-white/8 bg-black/20">
      <div className="max-h-[520px] overflow-auto">
        <table className="min-w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-950/92 backdrop-blur-md">
            <tr className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
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
                <tr key=${entry.id} className="border-t border-white/6 transition-colors hover:bg-white/[0.03]">
                  <td className="px-4 py-4 align-top">
                    <div className="flex items-start gap-3">
                      ${icon(entry.category_major === '三方AI' ? ACCENT.primary : entry.category_major === '自建AI' ? ACCENT.mint : ACCENT.amber)}
                      <div>
                        <div className="font-medium text-white">${entry.category_major} / ${entry.category_minor}</div>
                        <div className="mt-1 text-xs text-slate-500">#${entry.id} · ${entry.start_time_real || '--'}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-cyan-200">${formatNumber(entry.start_time_rel_s, 6)}s</td>
                  <td className="px-4 py-4 align-top text-white">${formatNumber((entry.latency_ms || 0) / 1000, 3)}s</td>
                  <td className="px-4 py-4 align-top text-xs text-slate-400">
                    <div>TTFB ${formatNumber(entry.ttfb_ms, 1)}ms</div>
                    <div className="mt-1">TTFT ${formatNumber(entry.ttft_ms, 1)}ms</div>
                    <div className="mt-1 text-slate-500">TPOT ${formatNumber(entry.tpot_ms_per_token, 1)} ms/token</div>
                  </td>
                  <td className="px-4 py-4 align-top text-xs text-slate-400">
                    <div>In ${formatCompact(entry.input_tokens || 0)}</div>
                    <div className="mt-1">Out ${formatCompact(entry.output_tokens || 0)}</div>
                  </td>
                  <td className="px-4 py-4 align-top text-xs text-slate-300">
                    <div>${flow.display}</div>
                    <div className="mt-1 text-slate-500">client ${flow.client}</div>
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

function ActivityFeed({ items }) {
  return html`
    <div className="space-y-3">
      ${items.map((item, idx) => html`
        <div key=${idx} className="rounded-[22px] border border-white/8 bg-white/[0.04] p-4">
          <div className="flex items-start gap-3">
            ${icon(item.tone)}
            <div>
              <div className="text-sm font-medium text-white">${item.title}</div>
              <div className="mt-1 text-xs leading-6 text-slate-500">${item.subtitle}</div>
            </div>
          </div>
        </div>
      `)}
    </div>
  `;
}

function UploadPanel({ uploadFileName, uploadProgress, onFileChange, onUpload, onClearEntries, busy }) {
  return html`
    <div className="rounded-[26px] border border-white/8 bg-white/[0.04] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-white">Upload PCAP</div>
          <div className="mt-1 text-xs text-slate-500">Upload and refresh all analytic modules</div>
        </div>
        <div className="rounded-full border border-cyan-300/15 bg-cyan-300/10 px-3 py-1 text-xs text-cyan-100">Realtime</div>
      </div>
      <label className="block cursor-pointer rounded-[26px] border border-dashed border-white/10 bg-black/20 px-4 py-6 text-center">
        <input type="file" accept=".pcap,.pcapng" className="hidden" onChange=${onFileChange} />
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-[20px] bg-violet-500/12 text-2xl">⤴</div>
        <div className="mt-4 text-sm font-medium text-white">${uploadFileName || '选择 .pcap / .pcapng 文件'}</div>
        <div className="mt-1 text-xs text-slate-500">Drag & drop or click to browse</div>
      </label>
      <div className="mt-4 overflow-hidden rounded-full bg-white/5">
        <div className="h-2 rounded-full bg-gradient-to-r from-violet-500 via-sky-500 to-cyan-400 transition-all duration-300" style=${{ width: `${uploadProgress}%` }}></div>
      </div>
      <div className="mt-2 text-xs text-slate-500">上传进度 ${uploadProgress}%</div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        <button onClick=${onUpload} disabled=${busy || !uploadFileName} className="rounded-[20px] border border-violet-300/20 bg-violet-400/12 px-4 py-3 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50">上传并分析</button>
        <button onClick=${onClearEntries} className="rounded-[20px] border border-white/8 bg-white/[0.04] px-4 py-3 text-sm text-slate-300">清空记录</button>
      </div>
    </div>
  `;
}

function ConfigPanel({ configs, form, setForm, onSubmit, onClear, onDelete }) {
  return html`
    <div className="rounded-[26px] border border-white/8 bg-white/[0.04] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-white">Self-hosted routing</div>
          <div className="mt-1 text-xs text-slate-500">Map internal model endpoints to business labels</div>
        </div>
        <button onClick=${onClear} className="rounded-[18px] border border-amber-300/15 bg-amber-300/10 px-3 py-2 text-xs text-amber-100">清空配置</button>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <input value=${form.name} onInput=${(e) => setForm((s) => ({ ...s, name: e.target.value }))} placeholder="小类名称，如 企业知识库" className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
        <input value=${form.server_ip} onInput=${(e) => setForm((s) => ({ ...s, server_ip: e.target.value }))} placeholder="服务端 IP:Port，如 192.168.101.1:443" className="rounded-[20px] border border-white/8 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500" />
      </div>
      <button onClick=${onSubmit} className="mt-3 w-full rounded-[20px] border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm font-medium text-cyan-50">保存自建配置</button>
      <div className="mt-4 space-y-2">
        ${configs.map((cfg) => html`
          <div key=${cfg.id} className="flex items-center justify-between rounded-[20px] border border-white/8 bg-black/20 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-white">${cfg.name}</div>
              <div className="mt-1 text-xs text-slate-500">${cfg.server_ip}</div>
            </div>
            <button onClick=${() => onDelete(cfg.id)} className="rounded-[16px] border border-white/8 px-3 py-2 text-xs text-slate-300">删除</button>
          </div>
        `)}
      </div>
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
      setStatus(`Updated ${new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`);
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

  const searchedEntries = useMemo(() => filterEntries(entries, search), [entries, search]);
  const trendData = useMemo(() => bucketEntries(searchedEntries), [searchedEntries]);
  const categoryStats = useMemo(() => buildCategoryStats(stats, searchedEntries), [stats, searchedEntries]);
  const activityFeed = useMemo(() => buildActivityFeed(searchedEntries, configs), [searchedEntries, configs]);
  const metricCards = useMemo(() => buildMetricCards(searchedEntries, stats), [searchedEntries, stats]);
  const performanceSummary = useMemo(() => buildPerformanceSummary(searchedEntries, stats), [searchedEntries, stats]);
  const healthRows = useMemo(() => buildHealthRows(searchedEntries), [searchedEntries]);
  const topFlows = useMemo(() => buildTopFlows(searchedEntries), [searchedEntries]);
  const visibleConfigs = useMemo(() => sourceConfigs(configs), [configs]);
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
      window.setTimeout(() => setUploadProgress(0), 1000);
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

  const applyFilters = async () => refreshAll(filters);
  const resetFilters = async () => {
    const cleared = { startReal: '', endReal: '', major: '', minor: '' };
    setFilters(cleared);
    await refreshAll(cleared);
  };

  return html`
    <div className="min-h-screen px-4 py-5 lg:px-6 xl:px-8">
      <div className="mx-auto grid max-w-[1780px] gap-6 xl:grid-cols-[290px_minmax(0,1fr)]">
        <${Sidebar} status=${status} />

        <main className="min-w-0">
          <${TopBar} search=${search} setSearch=${setSearch} status=${status} />

          <${HeroSpotlight} summary=${performanceSummary} trendData=${trendData} usingMock=${usingMock} />

          <section className="mt-6 grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
            ${metricCards.map((item) => html`<${MetricCard} key=${item.label} item=${item} />`)}
          </section>

          <section className="mt-6 grid gap-6 2xl:grid-cols-[minmax(0,1.65fr)_420px]">
            <${Panel}
              title="Primary traffic narrative"
              subtitle=${usingMock ? '当前无真实数据时使用 mock 预览以保证成品质感；上传真实 PCAP 后会自动切换。' : '以当前筛选条件为中心，展示请求量与输出 token 的主叙事图。'}
              action=${html`<div className="rounded-full border border-white/8 bg-white/[0.05] px-3 py-1.5 text-xs text-slate-400">${busy ? 'Syncing' : 'Live'}</div>`}
            >
              <${FilterBar} filters=${filters} setFilters=${setFilters} onApply=${applyFilters} onReset=${resetFilters} />
              <div className="mt-6"><${MainTrendChart} data=${trendData} /></div>
            </${Panel}>

            <div className="grid gap-6">
              <${Panel} title="AI segment mix" subtitle="用更精致的环形图和列表结构表达大类占比。">
                <${DistributionChart} rows=${categoryStats} />
              </${Panel}>
              <${Panel} title="Routing health" subtitle="高频小类、延迟与服务分数聚合到同一张运营卡片。">
                <${HealthList} rows=${healthRows} />
              </${Panel}>
            </div>
          </section>

          <section className="mt-6 grid gap-6 2xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)_360px]">
            <${Panel} title="Latency architecture" subtitle="TTFB、TTFT 与端到端 latency 统一在同一套克制配色里。">
              <${LatencyChart} rows=${categoryStats} />
            </${Panel}>
            <${Panel} title="Token dynamics" subtitle="输入 / 输出 token 变化使用更轻盈的线形表达。">
              <${TokenChart} data=${trendData} />
            </${Panel}>
            <${Panel} title="Top output flows" subtitle="优先突出对业务最有价值的高输出请求。">
              <${TopFlows} flows=${topFlows} />
            </${Panel}>
          </section>

          <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.55fr)_420px]">
            <${Panel} title="Request intelligence table" subtitle="强化层级、留白和暗色可读性，兼顾数据密度与产品质感。">
              <${RequestsTable} entries=${searchedEntries} />
            </${Panel}>
            <div className="grid gap-6">
              <${Panel} title="Recent activity" subtitle="最近请求、映射变更与状态脉搏。">
                <${ActivityFeed} items=${activityFeed} />
              </${Panel}>
              <${Panel} title="Control center" subtitle="将上传与配置纳入统一运营视图，而不是零散工具区。">
                <div className="grid gap-4">
                  <${UploadPanel}
                    uploadFileName=${selectedFile?.name || ''}
                    uploadProgress=${uploadProgress}
                    busy=${busy}
                    onFileChange=${(e) => setSelectedFile(e.target.files?.[0] || null)}
                    onUpload=${onUpload}
                    onClearEntries=${onClearEntries}
                  />
                  <${ConfigPanel}
                    configs=${visibleConfigs}
                    form=${configForm}
                    setForm=${setConfigForm}
                    onSubmit=${onSaveConfig}
                    onClear=${onClearConfig}
                    onDelete=${onDeleteConfig}
                  />
                </div>
              </${Panel}>
            </div>
          </section>

          <footer className="mt-6 flex flex-col gap-3 rounded-[30px] border border-white/8 bg-white/[0.04] px-5 py-4 text-sm text-slate-400 premium-shadow lg:flex-row lg:items-center lg:justify-between">
            <div><span className="text-white">Status:</span> ${status}</div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
              <span className="rounded-full border border-white/8 px-3 py-1">React</span>
              <span className="rounded-full border border-white/8 px-3 py-1">Tailwind CSS</span>
              <span className="rounded-full border border-white/8 px-3 py-1">Recharts</span>
              <span className="rounded-full border border-white/8 px-3 py-1">AI Gateway Data</span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  `;
}

createRoot(document.getElementById('app')).render(html`<${App} />`);
