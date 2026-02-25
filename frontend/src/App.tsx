import { motion } from 'framer-motion'
import { type FormEvent, useEffect, useMemo, useState } from 'react'
import type { Entry, MajorStat, SelfHosted } from './types'

const glass =
  'rounded-2xl border border-white/20 bg-white/10 shadow-2xl backdrop-blur-xl ring-1 ring-white/10'

const num = (v: number | null | undefined) => (v == null ? '-' : v.toFixed(1))

export function App() {
  const [entries, setEntries] = useState<Entry[]>([])
  const [stats, setStats] = useState<{ total_entries: number; total_input_tokens: number; total_output_tokens: number; rps: number; major_stats: MajorStat[] }>({
    total_entries: 0,
    total_input_tokens: 0,
    total_output_tokens: 0,
    rps: 0,
    major_stats: []
  })
  const [configs, setConfigs] = useState<SelfHosted[]>([])
  const [status, setStatus] = useState('')

  const cards = useMemo(
    () => [
      ['总 Entry 数', stats.total_entries],
      ['总输入 Token', stats.total_input_tokens],
      ['总输出 Token', stats.total_output_tokens],
      ['RPS (req/s)', num(stats.rps)]
    ],
    [stats]
  )

  const refresh = async () => {
    const [entriesRes, statsRes, cfgRes] = await Promise.all([
      fetch('/api/entries'),
      fetch('/api/stats'),
      fetch('/api/self-hosted')
    ])
    const entriesJson = await entriesRes.json()
    const statsJson = await statsRes.json()
    const cfgJson = await cfgRes.json()
    setEntries(entriesJson.items || [])
    setStats(statsJson)
    setConfigs(cfgJson.items || [])
  }

  useEffect(() => {
    void refresh()
  }, [])

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,#2e3f7a,transparent_45%),radial-gradient(circle_at_bottom_right,#113126,transparent_45%),linear-gradient(145deg,#090d1f,#111833)] text-slate-100">
      <main className="mx-auto max-w-[1500px] px-6 py-10">
        <motion.header initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45 }} className="mb-8">
          <h1 className="text-4xl font-semibold tracking-tight">AI 网关观测台</h1>
          <p className="mt-2 text-base text-slate-300">上传 PCAP、管理自建 AI 分类、实时查看指标。</p>
        </motion.header>

        <section className="mb-6 grid gap-4 md:grid-cols-4">
          {cards.map(([title, value], idx) => (
            <motion.article
              key={String(title)}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.08 }}
              className={`${glass} p-5`}
            >
              <h2 className="text-sm text-slate-300">{title}</h2>
              <p className="mt-3 text-3xl font-semibold">{value}</p>
            </motion.article>
          ))}
        </section>

        <section className="mb-6 grid gap-4 lg:grid-cols-2">
          <UploadCard setStatus={setStatus} onSuccess={refresh} />
          <ConfigCard configs={configs} setStatus={setStatus} onSuccess={refresh} />
        </section>

        <p className="mb-6 text-sm text-slate-300" aria-live="polite">{status}</p>

        <motion.section initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} className={`${glass} mb-6 p-5`}>
          <h3 className="mb-4 text-xl font-medium">按大类统计</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left">大类</th>
                  <th className="px-3 py-2 text-left">Entry数</th>
                  <th className="px-3 py-2 text-left">输入Token</th>
                  <th className="px-3 py-2 text-left">输出Token</th>
                  <th className="px-3 py-2 text-left">Avg TTFB (ms)</th>
                  <th className="px-3 py-2 text-left">Avg TTFT (ms)</th>
                  <th className="px-3 py-2 text-left">Avg Latency (ms)</th>
                </tr>
              </thead>
              <tbody>
                {stats.major_stats.map((row) => (
                  <tr key={row.category_major} className="border-t border-white/10">
                    <td className="px-3 py-2">{row.category_major}</td>
                    <td className="px-3 py-2">{row.total_entries}</td>
                    <td className="px-3 py-2">{row.total_input_tokens}</td>
                    <td className="px-3 py-2">{row.total_output_tokens}</td>
                    <td className="px-3 py-2">{num(row.avg_ttfb_ms)}</td>
                    <td className="px-3 py-2">{num(row.avg_ttft_ms)}</td>
                    <td className="px-3 py-2">{num(row.avg_latency_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.section>

        <motion.section initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} className={`${glass} p-5`}>
          <h3 className="mb-4 text-xl font-medium">Entry 列表</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-slate-300">
                <tr>
                  {['ID', '大类', '小类', '开始时间(真实)', '结束时间(真实)', '开始时间(相对s)', 'TTFB (ms)', 'TTFT (ms)', 'Latency (ms)', 'TPOT (ms/token)', '输入', '输出', 'Flow'].map((h) => (
                    <th key={h} className="px-3 py-2 text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id} className="border-t border-white/10 align-top">
                    <td className="px-3 py-2">{e.id}</td>
                    <td className="px-3 py-2">{e.category_major}</td>
                    <td className="px-3 py-2">{e.category_minor}</td>
                    <td className="px-3 py-2">{e.start_time_real}</td>
                    <td className="px-3 py-2">{e.end_time_real}</td>
                    <td className="px-3 py-2">{num(e.start_time_rel_s)}</td>
                    <td className="px-3 py-2">{num(e.ttfb_ms)}</td>
                    <td className="px-3 py-2">{num(e.ttft_ms)}</td>
                    <td className="px-3 py-2">{num(e.latency_ms)}</td>
                    <td className="px-3 py-2">{num(e.tpot_ms_per_token)}</td>
                    <td className="px-3 py-2">{e.input_tokens}</td>
                    <td className="px-3 py-2">{e.output_tokens}</td>
                    <td className="px-3 py-2 text-xs text-slate-300">{e.flow_key}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.section>
      </main>
    </div>
  )
}

function UploadCard({ onSuccess, setStatus }: { onSuccess: () => Promise<void>; setStatus: (s: string) => void }) {
  const upload = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const form = new FormData(e.currentTarget)
    const resp = await fetch('/api/upload', { method: 'POST', body: form })
    const data = await resp.json()
    setStatus(`上传完成，新增 ${data.inserted ?? 0} 条 entry。`)
    e.currentTarget.reset()
    await onSuccess()
  }

  const clearEntries = async () => {
    await fetch('/api/clear', { method: 'POST' })
    setStatus('历史 entry 已清空，序号已重置。')
    await onSuccess()
  }

  return (
    <motion.section initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} className={`${glass} p-5`}>
      <h3 className="text-xl font-medium">上传与记录管理</h3>
      <form onSubmit={upload} className="mt-4 space-y-3">
        <label className="block text-sm text-slate-300" aria-label="PCAP 文件上传">
          PCAP 文件
          <input aria-label="上传 pcap 文件" required name="file" type="file" accept=".pcap,.pcapng" className="mt-2 w-full rounded-2xl border border-white/20 bg-slate-950/40 p-3" />
        </label>
        <button aria-label="上传并分析 pcap" className="rounded-2xl bg-cyan-400/80 px-4 py-2 text-slate-900 transition hover:bg-cyan-300 active:translate-y-px">上传并分析</button>
        <button type="button" aria-label="清空 entry 记录" onClick={clearEntries} className="ml-3 rounded-2xl bg-rose-400/85 px-4 py-2 text-slate-950 transition hover:bg-rose-300 active:translate-y-px">清空记录</button>
      </form>
    </motion.section>
  )
}

function ConfigCard({ configs, onSuccess, setStatus }: { configs: SelfHosted[]; onSuccess: () => Promise<void>; setStatus: (s: string) => void }) {
  const addCfg = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const form = new FormData(e.currentTarget)
    await fetch('/api/self-hosted', { method: 'POST', body: form })
    setStatus('自建 AI 配置已保存。')
    e.currentTarget.reset()
    await onSuccess()
  }

  const clearCfg = async () => {
    await fetch('/api/self-hosted/clear', { method: 'POST' })
    setStatus('自建 AI 配置已清空，序号已重置。')
    await onSuccess()
  }

  return (
    <motion.section initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} className={`${glass} p-5`}>
      <h3 className="text-xl font-medium">自建 AI 分类配置</h3>
      <form onSubmit={addCfg} className="mt-4 grid gap-3 md:grid-cols-[1fr_1fr_auto]">
        <input aria-label="自建 AI 小类名称" required name="name" placeholder="小类名称，例如 小微助手" className="rounded-2xl border border-white/20 bg-slate-950/40 p-3" />
        <input aria-label="自建 AI 服务端 IP" required name="server_ip" placeholder="服务端 IP，例如 192.168.101.1" className="rounded-2xl border border-white/20 bg-slate-950/40 p-3" />
        <button aria-label="保存自建 AI 配置" className="rounded-2xl bg-indigo-400/80 px-4 py-2 text-slate-900 transition hover:bg-indigo-300 active:translate-y-px">保存</button>
      </form>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-slate-300">
            <tr>
              <th className="px-3 py-2 text-left">ID</th>
              <th className="px-3 py-2 text-left">小类</th>
              <th className="px-3 py-2 text-left">IP</th>
              <th className="px-3 py-2 text-left">操作</th>
            </tr>
          </thead>
          <tbody>
            {configs.map((c) => (
              <tr key={c.id} className="border-t border-white/10">
                <td className="px-3 py-2">{c.id}</td>
                <td className="px-3 py-2">{c.name}</td>
                <td className="px-3 py-2">{c.server_ip}</td>
                <td className="px-3 py-2">
                  <button aria-label={`删除配置 ${c.name}`} onClick={async () => { await fetch(`/api/self-hosted/${c.id}`, { method: 'DELETE' }); await onSuccess(); }} className="rounded-xl bg-white/10 px-3 py-1 hover:bg-white/20 active:translate-y-px">删除</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button aria-label="清空自建 AI 配置" onClick={clearCfg} className="mt-3 rounded-2xl bg-amber-300/85 px-4 py-2 text-slate-900 transition hover:bg-amber-200 active:translate-y-px">清空配置</button>
    </motion.section>
  )
}
