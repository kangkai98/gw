export type Entry = {
  id: number
  category_major: string
  category_minor: string
  flow_key: string
  start_time_real: string
  end_time_real: string
  start_time_rel_s: number
  ttfb_ms: number | null
  ttft_ms: number | null
  latency_ms: number | null
  tpot_ms_per_token: number | null
  input_tokens: number
  output_tokens: number
}

export type MajorStat = {
  category_major: string
  total_entries: number
  total_input_tokens: number
  total_output_tokens: number
  avg_ttfb_ms: number | null
  avg_ttft_ms: number | null
  avg_latency_ms: number | null
}

export type SelfHosted = {
  id: number
  name: string
  server_ip: string
}
