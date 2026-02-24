from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from scapy.all import IP, TCP, Raw, rdpcap

TOKEN_RE = re.compile(r"[\w\u4e00-\u9fff]+", re.UNICODE)
THIRD_PARTY_RULES: dict[str, tuple[str, ...]] = {
    "qwen api": ("qwen", "dashscope", "aliyun"),
    "doubao app": ("doubao", "volcengine", "ark.cn-beijing"),
    "openai api": ("openai", "chatgpt"),
}


@dataclass
class PacketMeta:
    ts: float
    src: str
    dst: str
    payload: str
    flow_key: str


def count_tokens(text: str) -> int:
    return len(TOKEN_RE.findall(text or ""))


def decode_payload(raw_bytes: bytes) -> str:
    return raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""


def fmt_real_time(ts: float) -> str:
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def extract_packets(pcap_path: Path) -> list[PacketMeta]:
    packets = rdpcap(str(pcap_path))
    result: list[PacketMeta] = []
    for p in packets:
        if IP not in p or TCP not in p:
            continue
        ip = p[IP]
        tcp = p[TCP]
        payload = decode_payload(bytes(tcp[Raw])) if Raw in tcp else ""
        flow_key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        result.append(PacketMeta(float(p.time), ip.src, ip.dst, payload, flow_key))
    return sorted(result, key=lambda x: x.ts)


def group_bi_flows(pkts: Iterable[PacketMeta]) -> dict[str, list[PacketMeta]]:
    groups: dict[str, list[PacketMeta]] = defaultdict(list)
    for p in pkts:
        left, right = p.flow_key.split("-")
        a = tuple(left.split(":"))
        b = tuple(right.split(":"))
        side1 = ":".join(a)
        side2 = ":".join(b)
        groups[f"{side1}-{side2}" if a <= b else f"{side2}-{side1}"].append(p)
    return groups


def infer_direction(flow_packets: list[PacketMeta]) -> tuple[str, str]:
    byte_by_src: dict[str, int] = defaultdict(int)
    for pkt in flow_packets:
        byte_by_src[pkt.src] += len(pkt.payload)
    client = min(byte_by_src, key=byte_by_src.get)
    server = next((ip for ip in byte_by_src if ip != client), client)
    return client, server


def split_entries(flow_packets: list[PacketMeta], gap_threshold: float) -> list[list[PacketMeta]]:
    if not flow_packets:
        return []
    entries = [[flow_packets[0]]]
    for pkt in flow_packets[1:]:
        if pkt.ts - entries[-1][-1].ts > gap_threshold:
            entries.append([pkt])
        else:
            entries[-1].append(pkt)
    return entries


def _pick_flow(flows: dict[str, list[PacketMeta]], ai_ip: str | None = None) -> tuple[str, list[PacketMeta]]:
    if ai_ip:
        for key, items in flows.items():
            if any(pkt.src == ai_ip or pkt.dst == ai_ip for pkt in items):
                return key, items
        raise ValueError(f"No flow matches ai_ip={ai_ip}")

    all_keywords = [kw for kws in THIRD_PARTY_RULES.values() for kw in kws]
    best_keyword_key, best_keyword_hits = "", 0
    best_fallback_key, best_bytes = "", -1
    for key, items in flows.items():
        merged = "\n".join(p.payload.lower() for p in items if p.payload)
        hits = sum(1 for kw in all_keywords if kw in merged)
        if hits > best_keyword_hits:
            best_keyword_key, best_keyword_hits = key, hits
        total_bytes = sum(len(p.payload) for p in items)
        if total_bytes > best_bytes:
            best_fallback_key, best_bytes = key, total_bytes

    selected = best_keyword_key if best_keyword_hits > 0 else best_fallback_key
    if not selected:
        raise ValueError("No TCP flow found in pcap")
    return selected, flows[selected]


def _extract_minor_from_payload(flow_packets: list[PacketMeta], fallback_ip: str) -> str:
    merged = "\n".join(p.payload for p in flow_packets if p.payload)
    host_match = re.search(r"(?im)^(?:host|authority)\s*:\s*([^\s]+)", merged)
    if host_match:
        return host_match.group(1)[:80]
    sni_like = re.search(r"([a-zA-Z0-9.-]+\.(?:com|cn|net|ai|io))", merged)
    if sni_like:
        return sni_like.group(1)[:80]
    words = TOKEN_RE.findall(merged)
    return (words[0][:30] if words else f"unknown-{fallback_ip}")


def classify_flow(
    flow_packets: list[PacketMeta],
    server_ip: str,
    self_hosted_configs: list[dict],
) -> tuple[str, str]:
    for cfg in self_hosted_configs:
        if cfg["server_ip"] == server_ip:
            return "自建AI", cfg["name"]

    text = "\n".join(pkt.payload.lower() for pkt in flow_packets if pkt.payload)
    for minor, keys in THIRD_PARTY_RULES.items():
        if any(k in text for k in keys):
            return "三方AI", minor

    return "实验AI", _extract_minor_from_payload(flow_packets, server_ip)


def _build_entry(
    entry_packets: list[PacketMeta],
    client_ip: str,
    server_ip: str,
    flow_key: str,
    major: str,
    minor: str,
    base_ts: float,
) -> dict:
    up = [p for p in entry_packets if p.src == client_ip]
    down = [p for p in entry_packets if p.src == server_ip]

    start_pkt = next((p for p in up if p.payload), up[0] if up else entry_packets[0])
    start_ts = start_pkt.ts
    first_down = next((p for p in down if p.payload), down[0] if down else None)
    first_token = next((p for p in down if count_tokens(p.payload) > 0), first_down)
    last_down = down[-1] if down else entry_packets[-1]

    ttfb_s = (first_down.ts - start_ts) if first_down else None
    ttft_s = (first_token.ts - start_ts) if first_token else None
    latency_s = (last_down.ts - start_ts) if last_down else None

    input_tokens = sum(count_tokens(p.payload) for p in up)
    output_tokens = sum(count_tokens(p.payload) for p in down)

    if latency_s is not None and ttft_s is not None and output_tokens > 0:
        tpot_ms = max((latency_s - ttft_s) * 1000, 0) / output_tokens
    else:
        tpot_ms = None

    return {
        "category_major": major,
        "category_minor": minor,
        "flow_key": flow_key,
        "start_time_real": fmt_real_time(start_ts),
        "end_time_real": fmt_real_time(last_down.ts if last_down else start_ts),
        "start_time_rel_s": round(start_ts - base_ts, 1),
        "ttfb_ms": round(ttfb_s * 1000, 1) if ttfb_s is not None else None,
        "ttft_ms": round(ttft_s * 1000, 1) if ttft_s is not None else None,
        "latency_ms": round(latency_s * 1000, 1) if latency_s is not None else None,
        "tpot_ms_per_token": round(tpot_ms, 1) if tpot_ms is not None else None,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def parse_pcap_to_entries(
    pcap_path: Path,
    gap_threshold: float,
    self_hosted_configs: list[dict],
    ai_ip: str | None = None,
) -> list[dict]:
    packets = extract_packets(pcap_path)
    if not packets:
        return []
    flows = group_bi_flows(packets)
    flow_key, ai_flow = _pick_flow(flows, ai_ip)
    client_ip, server_ip = infer_direction(ai_flow)
    major, minor = classify_flow(ai_flow, server_ip, self_hosted_configs)
    chunks = split_entries(ai_flow, gap_threshold)
    base_ts = packets[0].ts
    return [_build_entry(c, client_ip, server_ip, flow_key, major, minor, base_ts) for c in chunks if c]
