from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from scapy.all import IP, TCP, Raw, rdpcap

TOKEN_RE = re.compile(r"[\w\u4e00-\u9fff]+", re.UNICODE)
SOURCE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "qwen": ("qwen", "dashscope", "aliyun"),
    "doubao": ("doubao", "volcengine", "ark.cn-beijing"),
    "openai": ("openai", "chatgpt"),
    "experimental": ("exp", "test", "lab"),
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


def infer_source(flow_packets: list[PacketMeta], fallback_server_ip: str) -> str:
    text = "\n".join(pkt.payload.lower() for pkt in flow_packets if pkt.payload)
    for source, keys in SOURCE_KEYWORDS.items():
        if any(k in text for k in keys):
            return source
    return f"auto:{fallback_server_ip}"


def pick_ai_flow(flows: dict[str, list[PacketMeta]], ai_ip: str | None = None) -> tuple[str, list[PacketMeta]]:
    if ai_ip:
        for key, items in flows.items():
            if any(pkt.src == ai_ip or pkt.dst == ai_ip for pkt in items):
                return key, items
        raise ValueError(f"No flow matches ai_ip={ai_ip}")

    # 自动策略：优先匹配 host/sni 关键词，否则选择 payload 字节最大的流
    best_keyword_key = ""
    best_keyword_hits = 0
    best_fallback_key = ""
    best_fallback_score = -1

    all_keywords = [kw for kws in SOURCE_KEYWORDS.values() for kw in kws]
    for key, items in flows.items():
        joined = "\n".join(pkt.payload.lower() for pkt in items if pkt.payload)
        hits = sum(1 for kw in all_keywords if kw in joined)
        if hits > best_keyword_hits:
            best_keyword_hits = hits
            best_keyword_key = key

        bytes_sum = sum(len(pkt.payload) for pkt in items)
        if bytes_sum > best_fallback_score:
            best_fallback_key = key
            best_fallback_score = bytes_sum

    chosen_key = best_keyword_key if best_keyword_hits > 0 else best_fallback_key
    if not chosen_key:
        raise ValueError("No TCP flow found in pcap")
    return chosen_key, flows[chosen_key]


def infer_direction(flow_packets: list[PacketMeta]) -> tuple[str, str]:
    byte_by_src: dict[str, int] = defaultdict(int)
    for pkt in flow_packets:
        byte_by_src[pkt.src] += len(pkt.payload)
    client = min(byte_by_src, key=lambda ip: byte_by_src[ip])
    server_candidates = [ip for ip in byte_by_src if ip != client]
    server = server_candidates[0] if server_candidates else client
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


def build_entry_metrics(
    entry_packets: list[PacketMeta],
    client_ip: str,
    server_ip: str,
    source: str,
    flow_key: str,
    base_ts: float,
) -> dict:
    up = [p for p in entry_packets if p.src == client_ip]
    down = [p for p in entry_packets if p.src == server_ip]

    start_pkt = next((p for p in up if p.payload), up[0] if up else entry_packets[0])
    start_ts = start_pkt.ts

    first_down = next((p for p in down if p.payload), down[0] if down else None)
    ttfb = (first_down.ts - start_ts) if first_down else None

    first_token_pkt = next((p for p in down if count_tokens(p.payload) > 0), first_down)
    ttft = (first_token_pkt.ts - start_ts) if first_token_pkt else None

    last_down = down[-1] if down else None
    latency = (last_down.ts - start_ts) if last_down else None

    input_tokens = sum(count_tokens(p.payload) for p in up)
    output_tokens = sum(count_tokens(p.payload) for p in down)

    if latency is not None and ttft is not None and output_tokens > 0:
        tpot = max((latency - ttft), 0) / output_tokens
    else:
        tpot = None

    return {
        "source": source,
        "flow_key": flow_key,
        "start_time": round(start_ts - base_ts, 6),
        "ttfb": round(ttfb, 6) if ttfb is not None else None,
        "ttft": round(ttft, 6) if ttft is not None else None,
        "latency": round(latency, 6) if latency is not None else None,
        "tpot": round(tpot, 6) if tpot is not None else None,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def parse_pcap_to_entries(
    pcap_path: Path,
    source: str | None,
    gap_threshold: float,
    ai_ip: str | None = None,
) -> list[dict]:
    pkts = extract_packets(pcap_path)
    if not pkts:
        return []
    flows = group_bi_flows(pkts)
    flow_key, ai_flow_packets = pick_ai_flow(flows, ai_ip=ai_ip)
    client_ip, server_ip = infer_direction(ai_flow_packets)
    resolved_source = source or infer_source(ai_flow_packets, fallback_server_ip=server_ip)
    base_ts = pkts[0].ts
    chunks = split_entries(ai_flow_packets, gap_threshold=gap_threshold)
    return [build_entry_metrics(c, client_ip, server_ip, resolved_source, flow_key, base_ts) for c in chunks if c]
