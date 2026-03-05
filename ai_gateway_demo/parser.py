from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Iterable

from scapy.all import IP, TCP, Raw, rdpcap

TOKEN_RE = re.compile(r"[\w\u4e00-\u9fff]+", re.UNICODE)
THIRD_PARTY_RULES: dict[str, tuple[str, ...]] = {
    "qwen api": ("qwen", "dashscope", "aliyun"),
    "doubao app": ("doubao", "volcengine", "ark.cn-beijing", "coze"),
    "openai api": ("openai", "chatgpt"),
    "claude api": ("anthropic", "claude"),
    "gemini api": ("googleapis", "gemini", "generativelanguage"),
    "文心一言": ("baidu", "wenxin", "ernie"),
    "讯飞星火": ("xfyun", "spark"),
    "kimi": ("moonshot", "kimi"),
    "智谱ai": ("zhipu", "bigmodel"),
    "deepseek": ("deepseek",),
}
HEADER_LIKE_PREFIXES = ("http/", "content-", "date:", "server:", "x-", ":status")


@dataclass
class PacketMeta:
    ts: float
    src: str
    dst: str
    payload: str
    flow_key: str
    raw: bytes
    sni: str | None


@dataclass
class FlowFeatures:
    flow_key: str
    client_ip: str
    server_ip: str
    packets: list[PacketMeta]
    total_bytes: int
    up_bytes: int
    down_bytes: int
    up_non_empty: int
    down_non_empty: int
    tokenish_down: int
    host_hits: int
    sni_hits: int
    is_https: bool


def count_tokens(text: str) -> int:
    return len(TOKEN_RE.findall(text or ""))


def decode_payload(raw_bytes: bytes) -> str:
    return raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""


def fmt_real_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _extract_tls_sni(raw: bytes) -> str | None:
    if len(raw) < 10:
        return None
    try:
        if raw[0] != 0x16:
            return None
        idx = 5
        if raw[idx] != 0x01:
            return None
        idx += 4
        idx += 2 + 32
        session_len = raw[idx]
        idx += 1 + session_len
        cs_len = int.from_bytes(raw[idx : idx + 2], "big")
        idx += 2 + cs_len
        comp_len = raw[idx]
        idx += 1 + comp_len
        ext_len = int.from_bytes(raw[idx : idx + 2], "big")
        idx += 2
        ext_end = idx + ext_len

        while idx + 4 <= ext_end and idx + 4 <= len(raw):
            ext_type = int.from_bytes(raw[idx : idx + 2], "big")
            ext_data_len = int.from_bytes(raw[idx + 2 : idx + 4], "big")
            idx += 4
            ext_data = raw[idx : idx + ext_data_len]
            idx += ext_data_len
            if ext_type != 0x0000 or len(ext_data) < 5:
                continue
            list_len = int.from_bytes(ext_data[:2], "big")
            pos = 2
            end = min(2 + list_len, len(ext_data))
            while pos + 3 <= end:
                name_type = ext_data[pos]
                name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
                pos += 3
                if pos + name_len > end:
                    break
                if name_type == 0:
                    return ext_data[pos : pos + name_len].decode("utf-8", errors="ignore").lower()
                pos += name_len
    except Exception:
        return None
    return None


def _has_token_payload(payload: str) -> bool:
    if not payload:
        return False
    lowered = payload.strip().lower()
    if not lowered:
        return False
    if any(lowered.startswith(prefix) for prefix in HEADER_LIKE_PREFIXES):
        return False
    if lowered.startswith("{") and "choices" not in lowered and "content" not in lowered:
        return False
    return count_tokens(payload) > 0


def extract_packets(pcap_path: Path) -> list[PacketMeta]:
    packets = rdpcap(str(pcap_path))
    result: list[PacketMeta] = []
    for p in packets:
        if IP not in p or TCP not in p:
            continue
        ip = p[IP]
        tcp = p[TCP]
        raw_bytes = bytes(tcp[Raw]) if Raw in tcp else b""
        result.append(
            PacketMeta(
                ts=float(p.time),
                src=ip.src,
                dst=ip.dst,
                payload=decode_payload(raw_bytes),
                flow_key=f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}",
                raw=raw_bytes,
                sni=_extract_tls_sni(raw_bytes),
            )
        )
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
        byte_by_src[pkt.src] += len(pkt.raw)
    client = min(byte_by_src, key=byte_by_src.get)
    server = next((ip for ip in byte_by_src if ip != client), client)
    return client, server


def _extract_flow_features(flow_key: str, packets: list[PacketMeta]) -> FlowFeatures:
    client_ip, server_ip = infer_direction(packets)
    up = [p for p in packets if p.src == client_ip]
    down = [p for p in packets if p.src == server_ip]
    merged_payload = "\n".join(p.payload.lower() for p in packets if p.payload)
    sni_text = "\n".join((p.sni or "") for p in packets if p.sni)
    all_keywords = [kw for kws in THIRD_PARTY_RULES.values() for kw in kws]

    return FlowFeatures(
        flow_key=flow_key,
        client_ip=client_ip,
        server_ip=server_ip,
        packets=packets,
        total_bytes=sum(len(p.raw) for p in packets),
        up_bytes=sum(len(p.raw) for p in up),
        down_bytes=sum(len(p.raw) for p in down),
        up_non_empty=sum(1 for p in up if p.payload),
        down_non_empty=sum(1 for p in down if p.payload),
        tokenish_down=sum(1 for p in down if _has_token_payload(p.payload)),
        host_hits=sum(1 for kw in all_keywords if kw in merged_payload),
        sni_hits=sum(1 for kw in all_keywords if kw in sni_text),
        is_https=any(p.src == client_ip and p.sni for p in packets),
    )


def _flow_ai_score(features: FlowFeatures, self_hosted_configs: list[dict]) -> float:
    self_hosted_ips = {cfg["server_ip"] for cfg in self_hosted_configs}

    score = 0.0
    if features.server_ip in self_hosted_ips:
        score += 90.0
    score += min(features.total_bytes / 600.0, 20.0)
    score += features.sni_hits * 22.0
    score += features.host_hits * 10.0
    score += min(features.tokenish_down * 4.0, 20.0)

    if features.is_https:
        score += 6.0
    if features.up_non_empty > 0 and features.down_non_empty > 0:
        score += 6.0

    balance = min(features.up_bytes, features.down_bytes) / max(features.total_bytes, 1)
    score += balance * 20.0

    return score


def pick_ai_flows(flows: dict[str, list[PacketMeta]], self_hosted_configs: list[dict]) -> list[FlowFeatures]:
    ranked: list[tuple[FlowFeatures, float]] = []
    for flow_key, packets in flows.items():
        feats = _extract_flow_features(flow_key, packets)
        ranked.append((feats, _flow_ai_score(feats, self_hosted_configs)))

    ranked.sort(key=lambda x: x[1], reverse=True)
    if not ranked:
        return []

    max_score = ranked[0][1]
    dynamic_gate = max(14.0, max_score * 0.35)
    selected = [feats for feats, score in ranked if score >= dynamic_gate]
    return selected if selected else [ranked[0][0]]


def _extract_minor_from_payload(flow_packets: list[PacketMeta], fallback_ip: str) -> str:
    merged = "\n".join(p.payload for p in flow_packets if p.payload)
    host_match = re.search(r"(?im)^(?:host|authority)\s*:\s*([^\s]+)", merged)
    if host_match:
        host = host_match.group(1)[:80].lower()
        for minor, keys in THIRD_PARTY_RULES.items():
            if any(k in host for k in keys):
                return minor
        return host
    words = TOKEN_RE.findall(merged)
    return words[0][:30] if words else f"exp-{fallback_ip}"


def classify_flow(flow_packets: list[PacketMeta], client_ip: str, server_ip: str, self_hosted_configs: list[dict]) -> tuple[str, str]:
    for cfg in self_hosted_configs:
        if cfg["server_ip"] == server_ip:
            return "自建AI", cfg["name"]

    sni_text = "\n".join((pkt.sni or "") for pkt in flow_packets if pkt.sni)
    if any(pkt.src == client_ip and pkt.sni for pkt in flow_packets):
        for minor, keys in THIRD_PARTY_RULES.items():
            if any(k in sni_text for k in keys):
                return "三方AI", minor

    return "实验AI", _extract_minor_from_payload(flow_packets, server_ip)


def split_qa_turns(flow_packets: list[PacketMeta], client_ip: str, server_ip: str) -> list[list[PacketMeta]]:
    ordered = sorted(flow_packets, key=lambda p: p.ts)
    if not ordered:
        return []

    up_indices = [i for i, p in enumerate(ordered) if p.src == client_ip and p.payload]
    if not up_indices:
        return [ordered]

    up_gaps = [ordered[b].ts - ordered[a].ts for a, b in zip(up_indices, up_indices[1:]) if ordered[b].ts > ordered[a].ts]
    gap_threshold = max(1.0, median(up_gaps) * 2.2) if up_gaps else 2.0

    request_starts = [up_indices[0]]
    for prev, cur in zip(up_indices, up_indices[1:]):
        cur_gap = ordered[cur].ts - ordered[prev].ts
        if cur_gap >= gap_threshold:
            request_starts.append(cur)

    chunks: list[list[PacketMeta]] = []
    for idx, start in enumerate(request_starts):
        end = request_starts[idx + 1] if idx + 1 < len(request_starts) else len(ordered)
        chunk = ordered[start:end]

        up_count = sum(1 for p in chunk if p.src == client_ip and p.payload)
        down_count = sum(1 for p in chunk if p.src == server_ip and p.payload)
        if up_count == 0:
            continue

        if down_count == 0 and idx + 1 < len(request_starts):
            next_start = request_starts[idx + 1]
            merged = ordered[start:next_start]
            if any(p.src == server_ip and p.payload for p in merged):
                chunk = merged

        chunks.append(chunk)

    return chunks


def _build_entry(entry_packets: list[PacketMeta], client_ip: str, server_ip: str, flow_key: str, major: str, minor: str, base_ts: float) -> dict:
    ordered = sorted(entry_packets, key=lambda p: p.ts)
    up = [p for p in ordered if p.src == client_ip]
    down_all = [p for p in ordered if p.src == server_ip]

    start_pkt = next((p for p in up if p.payload), up[0] if up else ordered[0])
    start_ts = start_pkt.ts
    down_after_start = [p for p in down_all if p.ts >= start_ts]

    first_down_pkt = next((p for p in down_after_start if p.payload and p.ts > start_ts), None)
    if first_down_pkt is None:
        first_down_pkt = next((p for p in down_after_start if p.payload), None)

    first_token_pkt = next((p for p in down_after_start if _has_token_payload(p.payload) and p.ts > start_ts), None)
    if first_token_pkt is None:
        first_token_pkt = next((p for p in down_after_start if _has_token_payload(p.payload)), None)

    last_down = down_after_start[-1] if down_after_start else ordered[-1]

    ttfb_s = max((first_down_pkt.ts - start_ts), 0.0) if first_down_pkt else None
    ttft_s = max((first_token_pkt.ts - start_ts), 0.0) if first_token_pkt else None
    latency_s = max((last_down.ts - start_ts), 0.0) if last_down else None

    if ttft_s is not None and ttfb_s is not None and ttft_s < ttfb_s:
        ttft_s = ttfb_s

    input_tokens = sum(count_tokens(p.payload) for p in up)
    output_tokens = sum(count_tokens(p.payload) for p in down_after_start)

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


def _is_valid_entry(entry: dict) -> bool:
    latency = entry.get("latency_ms")
    ttft = entry.get("ttft_ms")
    input_tokens = entry.get("input_tokens") or 0
    output_tokens = entry.get("output_tokens") or 0

    if latency is None or latency <= 0:
        return False
    if ttft is None or ttft <= 0:
        return False
    if input_tokens <= 0 or output_tokens <= 0:
        return False
    return True


def parse_pcap_to_entries(pcap_path: Path, self_hosted_configs: list[dict]) -> list[dict]:
    packets = extract_packets(pcap_path)
    if not packets:
        return []

    flows = group_bi_flows(packets)
    ai_flows = pick_ai_flows(flows, self_hosted_configs=self_hosted_configs)
    base_ts = packets[0].ts

    entries: list[dict] = []
    for flow in ai_flows:
        major, minor = classify_flow(
            flow.packets,
            client_ip=flow.client_ip,
            server_ip=flow.server_ip,
            self_hosted_configs=self_hosted_configs,
        )
        chunks = split_qa_turns(flow.packets, flow.client_ip, flow.server_ip)
        entries.extend(
            _build_entry(chunk, flow.client_ip, flow.server_ip, flow.flow_key, major, minor, base_ts)
            for chunk in chunks
            if chunk
        )

    entries.sort(key=lambda e: (e["start_time_rel_s"], e["start_time_real"]))
    return [entry for entry in entries if _is_valid_entry(entry)]
