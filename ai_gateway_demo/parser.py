from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from scapy.all import IP, TCP, Raw, rdpcap

TOKEN_RE = re.compile(r"[\w\u4e00-\u9fff]+", re.UNICODE)

THIRD_PARTY_HINTS: dict[str, tuple[str, ...]] = {
    "qwen api": ("qwen", "dashscope", "aliyun"),
    "豆包 app": ("doubao", "volcengine", "ark"),
    "openai api": ("openai", "chatgpt", "gpt-"),
}
AI_TRAFFIC_HINTS = (
    "prompt",
    "messages",
    "assistant",
    "completion",
    "stream",
    "data:",
)


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
    if not raw_bytes:
        return ""
    return raw_bytes.decode("utf-8", errors="ignore")


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
        result.append(PacketMeta(ts=float(p.time), src=ip.src, dst=ip.dst, payload=payload, flow_key=flow_key))
    return sorted(result, key=lambda x: x.ts)


def group_bi_flows(pkts: Iterable[PacketMeta]) -> dict[str, list[PacketMeta]]:
    groups: dict[str, list[PacketMeta]] = defaultdict(list)
    for p in pkts:
        left, right = p.flow_key.split("-")
        a = tuple(left.split(":"))
        b = tuple(right.split(":"))
        side1 = ":".join(a)
        side2 = ":".join(b)
        normalized = f"{side1}-{side2}" if a <= b else f"{side2}-{side1}"
        groups[normalized].append(p)
    return groups


def infer_direction(flow_packets: list[PacketMeta]) -> tuple[str, str]:
    byte_by_src: dict[str, int] = defaultdict(int)
    for pkt in flow_packets:
        byte_by_src[pkt.src] += len(pkt.payload)
    client = min(byte_by_src, key=lambda ip: byte_by_src[ip])
    server_candidates = [ip for ip in byte_by_src if ip != client]
    server = server_candidates[0] if server_candidates else client
    return client, server


def score_flow_for_ai(flow_packets: list[PacketMeta]) -> int:
    text = "\n".join(p.payload.lower() for p in flow_packets if p.payload)
    bytes_sum = sum(len(p.payload) for p in flow_packets)
    hint_hits = sum(1 for h in AI_TRAFFIC_HINTS if h in text)
    return hint_hits * 1000 + bytes_sum


def pick_ai_flow(flows: dict[str, list[PacketMeta]], ai_ip: str | None = None) -> tuple[str, list[PacketMeta]]:
    if ai_ip:
        for key, items in flows.items():
            if any(pkt.src == ai_ip or pkt.dst == ai_ip for pkt in items):
                return key, items
        raise ValueError(f"No flow matches ai_ip={ai_ip}")

    best_key = ""
    best_score = -1
    for key, items in flows.items():
        score = score_flow_for_ai(items)
        if score > best_score:
            best_key = key
            best_score = score
    if not best_key:
        raise ValueError("No TCP flow found in pcap")
    return best_key, flows[best_key]


def classify_source(
    flow_packets: list[PacketMeta],
    server_ip: str,
    self_hosted_configs: list[dict[str, str]],
) -> tuple[str, str]:
    for cfg in self_hosted_configs:
        if server_ip == cfg["ip"]:
            return "自建AI", cfg["label"]

    text = "\n".join(p.payload.lower() for p in flow_packets if p.payload)
    for minor, hints in THIRD_PARTY_HINTS.items():
        if any(h in text for h in hints):
            return "三方AI", minor

    first_line = next((p.payload.strip().splitlines()[0] for p in flow_packets if p.payload.strip()), "unknown")
    return "实验AI", first_line[:40]


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


def to_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def build_entry_metrics(
    entry_packets: list[PacketMeta],
    client_ip: str,
    server_ip: str,
    source_major: str,
    source_minor: str,
    flow_key: str,
    pcap_base_ts: float,
) -> dict:
    up = [p for p in entry_packets if p.src == client_ip]
    down = [p for p in entry_packets if p.src == server_ip]

    start_pkt = next((p for p in up if p.payload), up[0] if up else entry_packets[0])
    start_ts = start_pkt.ts

    first_down = next((p for p in down if p.payload), down[0] if down else None)
    ttfb_ms = ((first_down.ts - start_ts) * 1000.0) if first_down else None

    first_token_pkt = next((p for p in down if count_tokens(p.payload) > 0), first_down)
    ttft_ms = ((first_token_pkt.ts - start_ts) * 1000.0) if first_token_pkt else None

    last_down = down[-1] if down else None
    latency_ms = ((last_down.ts - start_ts) * 1000.0) if last_down else None

    input_tokens = sum(count_tokens(p.payload) for p in up)
    output_tokens = sum(count_tokens(p.payload) for p in down)

    if latency_ms is not None and ttft_ms is not None and output_tokens > 0:
        tpot_ms_per_token = max((latency_ms - ttft_ms), 0) / output_tokens
    else:
        tpot_ms_per_token = None

    end_ts = (start_ts + latency_ms / 1000.0) if latency_ms is not None else None

    return {
        "source_major": source_major,
        "source_minor": source_minor,
        "flow_key": flow_key,
        "start_time_s": round(start_ts - pcap_base_ts, 1),
        "start_time_dt": to_iso(start_ts),
        "end_time_dt": to_iso(end_ts),
        "ttfb_ms": round(ttfb_ms, 1) if ttfb_ms is not None else None,
        "ttft_ms": round(ttft_ms, 1) if ttft_ms is not None else None,
        "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
        "tpot_ms_per_token": round(tpot_ms_per_token, 1) if tpot_ms_per_token is not None else None,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def parse_pcap_to_entries(
    pcap_path: Path,
    gap_threshold: float,
    self_hosted_configs: list[dict[str, str]],
    ai_ip: str | None = None,
) -> list[dict]:
    pkts = extract_packets(pcap_path)
    if not pkts:
        return []

    flows = group_bi_flows(pkts)
    flow_key, ai_flow_packets = pick_ai_flow(flows, ai_ip=ai_ip)
    client_ip, server_ip = infer_direction(ai_flow_packets)
    source_major, source_minor = classify_source(ai_flow_packets, server_ip, self_hosted_configs)

    chunks = split_entries(ai_flow_packets, gap_threshold=gap_threshold)
    return [
        build_entry_metrics(
            c,
            client_ip,
            server_ip,
            source_major,
            source_minor,
            flow_key,
            pkts[0].ts,
        )
        for c in chunks
        if c
    ]
