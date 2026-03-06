from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from scapy.all import IP, TCP, Raw, rdpcap

# ====== switches ======
DEBUG_PRINT = True

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

TLS_HANDSHAKE = 0x16
TLS_APPDATA = 0x17
TLS_ALERT = 0x15
TLS_CCS = 0x14


@dataclass
class PacketMeta:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload: str
    flow_key: str
    raw: bytes
    sni: str | None


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
        if raw[0] != TLS_HANDSHAKE:
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
            e_len = int.from_bytes(raw[idx + 2 : idx + 4], "big")
            idx += 4
            ext_data = raw[idx : idx + e_len]
            idx += e_len
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


def _tls_content_type(raw: bytes) -> int | None:
    if not raw or len(raw) < 5:
        return None
    t = raw[0]
    if t in (TLS_HANDSHAKE, TLS_APPDATA, TLS_ALERT, TLS_CCS):
        return t
    return None


def _looks_like_tls_record(raw: bytes) -> bool:
    if not raw or len(raw) < 5:
        return False
    t = raw[0]
    if t not in (TLS_HANDSHAKE, TLS_APPDATA, TLS_ALERT, TLS_CCS):
        return False
    if raw[1] != 0x03:
        return False
    if raw[2] not in (0x00, 0x01, 0x02, 0x03, 0x04):
        return False
    return True


def _is_https_flow(flow_packets: list[PacketMeta], client_ip: str) -> bool:
    if any(pkt.src == client_ip and pkt.sni for pkt in flow_packets):
        return True
    return any(_looks_like_tls_record(p.raw) for p in flow_packets if p.raw)


def _is_app_payload(pkt: PacketMeta, is_https: bool) -> bool:
    if not pkt.raw:
        return False
    if not is_https:
        return True
    t = _tls_content_type(pkt.raw)
    if t == TLS_APPDATA:
        return True
    if t is None:
        return True
    return False


def extract_packets(pcap_path: Path) -> list[PacketMeta]:
    packets = rdpcap(str(pcap_path))
    result: list[PacketMeta] = []
    for p in packets:
        if IP not in p or TCP not in p:
            continue
        ip = p[IP]
        tcp = p[TCP]
        raw_bytes = bytes(tcp[Raw]) if Raw in tcp else b""
        payload = decode_payload(raw_bytes)
        flow_key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        result.append(
            PacketMeta(
                ts=float(p.time),
                src=str(ip.src),
                dst=str(ip.dst),
                sport=int(tcp.sport),
                dport=int(tcp.dport),
                payload=payload,
                flow_key=flow_key,
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
    ips = sorted({p.src for p in flow_packets} | {p.dst for p in flow_packets})
    if len(ips) < 2:
        return (ips[0], ips[0]) if ips else ("", "")

    sni_senders = [p.src for p in flow_packets if p.sni]
    if sni_senders:
        client = max(set(sni_senders), key=sni_senders.count)
        server = next((ip for ip in ips if ip != client), client)
        return client, server

    server_port_candidates = {443, 80, 8443, 8080}
    port_hits: dict[str, int] = defaultdict(int)
    for p in flow_packets:
        if p.sport in server_port_candidates:
            port_hits[p.src] += 1
        if p.dport in server_port_candidates:
            port_hits[p.dst] += 1
    if port_hits:
        server = max(port_hits, key=port_hits.get)
        client = next((ip for ip in ips if ip != server), server)
        return client, server

    byte_by_src: dict[str, int] = defaultdict(int)
    for pkt in flow_packets:
        byte_by_src[pkt.src] += len(pkt.raw)
    client = min(byte_by_src, key=byte_by_src.get)
    server = next((ip for ip in byte_by_src if ip != client), client)
    return client, server


def classify_flow(
    flow_packets: list[PacketMeta],
    client_ip: str,
    server_ip: str,
    self_hosted_configs: list[dict],
) -> tuple[str, str]:
    for cfg in self_hosted_configs:
        if cfg["server_ip"] == server_ip:
            return "自建AI", cfg.get("name", server_ip)

    sni_text = "\n".join((pkt.sni or "") for pkt in flow_packets if pkt.sni)
    if _is_https_flow(flow_packets, client_ip):
        for minor, keys in THIRD_PARTY_RULES.items():
            if any(k in sni_text for k in keys):
                return "三方AI", minor

    merged = "\n".join(p.payload for p in flow_packets if p.payload)
    host_match = re.search(r"(?im)^(?:host|authority)\s*:\s*([^\s]+)", merged)
    if host_match:
        return "实验AI", host_match.group(1)[:80].lower()
    words = TOKEN_RE.findall(merged)
    return "实验AI", (words[0][:30] if words else f"exp-{server_ip}")


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


def _find_stream_start(
    down_app: list[PacketMeta],
    anchor_ts: float,
    *,
    gap_before_s: float = 0.35,
    lookahead_s: float = 1.0,
    small_len_max: int = 700,
    small_need: int = 5,
    start_len_min: int = 400,
) -> PacketMeta | None:
    d = [p for p in down_app if p.ts >= anchor_ts]
    if not d:
        return None

    for i in range(len(d)):
        cur = d[i]
        if cur.ts <= anchor_ts:
            continue

        prev_ts = d[i - 1].ts if i > 0 else anchor_ts
        gap = cur.ts - prev_ts
        if gap < gap_before_s:
            continue
        if len(cur.raw) < start_len_min:
            continue

        t_end = cur.ts + lookahead_s
        small_cnt = 0
        j = i + 1
        while j < len(d) and d[j].ts <= t_end:
            if 0 < len(d[j].raw) <= small_len_max:
                small_cnt += 1
            j += 1

        if small_cnt >= small_need:
            return cur

    return None


def _streaming_score(flow_items: list[PacketMeta], client_ip: str) -> float:
    is_https = _is_https_flow(flow_items, client_ip)
    up_app = [p for p in flow_items if p.src == client_ip and _is_app_payload(p, is_https)]
    down_app = [p for p in flow_items if p.src != client_ip and _is_app_payload(p, is_https)]
    if not up_app or not down_app:
        return 0.0

    req_start_ts = up_app[0].ts
    first_down = next((p for p in down_app if p.ts > req_start_ts), None)
    if first_down is not None:
        candidates = [p for p in up_app if p.ts < first_down.ts]
        req_end_ts = candidates[-1].ts if candidates else up_app[-1].ts
    else:
        req_end_ts = up_app[-1].ts

    start = _find_stream_start(down_app, req_end_ts, small_len_max=320, small_need=6, start_len_min=400)
    if not start:
        return 0.0

    t_end = start.ts + 1.0
    small_cnt = sum(1 for p in down_app if start.ts < p.ts <= t_end and 0 < len(p.raw) <= 320)
    return 60.0 + min(small_cnt, 20) * 3.0


def _pick_flow(flows: dict[str, list[PacketMeta]], self_hosted_configs: list[dict]) -> tuple[str, list[PacketMeta]]:
    self_hosted_ips = {cfg["server_ip"] for cfg in self_hosted_configs}
    all_keywords = [kw for kws in THIRD_PARTY_RULES.values() for kw in kws]

    best_key = ""
    best_score = float("-inf")
    for key, items in flows.items():
        client_ip, server_ip = infer_direction(items)
        text = "\n".join(p.payload.lower() for p in items if p.payload)
        sni_text = "\n".join((p.sni or "") for p in items if p.sni)

        score = 0.0
        if server_ip in self_hosted_ips:
            score += 60.0
        score += 20.0 * sum(1 for kw in all_keywords if kw in sni_text)
        score += 8.0 * sum(1 for kw in all_keywords if kw in text)
        score += _streaming_score(items, client_ip)
        if _is_https_flow(items, client_ip):
            score += 6.0
        score += sum(len(p.raw) for p in items) / 800.0

        if score > best_score:
            best_score = score
            best_key = key

    if not best_key:
        raise ValueError("No TCP flow found in pcap")
    return best_key, flows[best_key]


def split_entries(flow_packets: list[PacketMeta], gap_threshold: float = 2.0) -> list[list[PacketMeta]]:
    if not flow_packets:
        return []
    ordered = sorted(flow_packets, key=lambda p: p.ts)
    chunks: list[list[PacketMeta]] = [[ordered[0]]]
    for pkt in ordered[1:]:
        if pkt.ts - chunks[-1][-1].ts > gap_threshold:
            chunks.append([pkt])
        else:
            chunks[-1].append(pkt)
    return chunks


def _build_entry(
    entry_packets: list[PacketMeta],
    client_ip: str,
    server_ip: str,
    flow_key: str,
    major: str,
    minor: str,
    base_ts: float,
) -> dict:
    ordered = sorted(entry_packets, key=lambda p: p.ts)
    is_https = _is_https_flow(ordered, client_ip)

    up_app = [p for p in ordered if p.src == client_ip and _is_app_payload(p, is_https)]
    down_app = [p for p in ordered if p.src == server_ip and _is_app_payload(p, is_https)]

    start_pkt = up_app[0] if up_app else ordered[0]
    req_start_ts = start_pkt.ts

    first_down_after_start = next((p for p in down_app if p.ts > req_start_ts), None) or next(
        (p for p in down_app if p.ts >= req_start_ts), None
    )

    first_down_any = next((p for p in down_app if p.ts > req_start_ts), None)
    if up_app:
        if first_down_any is not None:
            candidates = [p for p in up_app if p.ts < first_down_any.ts]
            req_end_pkt = candidates[-1] if candidates else up_app[-1]
        else:
            req_end_pkt = up_app[-1]
    else:
        req_end_pkt = start_pkt
    req_end_ts = req_end_pkt.ts

    ttfb_end_pkt = first_down_after_start
    ttfb_s = max((ttfb_end_pkt.ts - req_start_ts), 0.0) if ttfb_end_pkt else None

    stream_start = _find_stream_start(
        down_app,
        req_start_ts,
        gap_before_s=0.35,
        lookahead_s=1.2,
        small_len_max=700,
        small_need=6,
        start_len_min=400,
    )

    if stream_start is not None:
        ttft_end_pkt = stream_start
        ttft_s = max(ttft_end_pkt.ts - req_start_ts, 0.0)
    else:
        down_after_start_all = [p for p in ordered if p.src == server_ip and p.ts >= req_start_ts]
        first_token_pkt = (
            next((p for p in down_after_start_all if _has_token_payload(p.payload) and p.ts > req_start_ts), None)
            or next((p for p in down_after_start_all if _has_token_payload(p.payload)), None)
        )
        ttft_end_pkt = first_token_pkt or first_down_after_start
        ttft_s = max((ttft_end_pkt.ts - req_start_ts), 0.0) if ttft_end_pkt else None

    if ttft_s is not None and ttfb_s is not None and ttft_s < ttfb_s:
        ttft_s = ttfb_s
        ttft_end_pkt = ttfb_end_pkt

    down_after_start = [p for p in down_app if p.ts >= req_start_ts]
    last_down = down_after_start[-1] if down_after_start else (down_app[-1] if down_app else ordered[-1])
    latency_end_pkt = last_down
    latency_s = max((latency_end_pkt.ts - req_start_ts), 0.0) if latency_end_pkt else None

    input_tokens = sum(count_tokens(p.payload) for p in ordered if p.src == client_ip)
    output_tokens = sum(count_tokens(p.payload) for p in ordered if p.src == server_ip and p.ts >= req_start_ts)

    if latency_s is not None and ttft_s is not None and output_tokens > 0:
        tpot_ms = max((latency_s - ttft_s) * 1000, 0) / output_tokens
    else:
        tpot_ms = None

    if DEBUG_PRINT:
        base = base_ts

        def _rel6(p: Optional[PacketMeta]) -> str:
            return f"{(p.ts - base):.6f}" if p is not None else "None"

        print(
            f"[ENTRY] flow={flow_key} req_start=+{_rel6(start_pkt)} req_end=+{_rel6(req_end_pkt)} | "
            f"TTFB +{_rel6(start_pkt)}->+{_rel6(ttfb_end_pkt)} | "
            f"TTFT +{_rel6(start_pkt)}->+{_rel6(ttft_end_pkt)} | "
            f"LAT +{_rel6(start_pkt)}->+{_rel6(latency_end_pkt)}"
        )

    return {
        "category_major": major,
        "category_minor": minor,
        "flow_key": flow_key,
        "start_time_real": fmt_real_time(req_start_ts),
        "end_time_real": fmt_real_time(latency_end_pkt.ts if latency_end_pkt else req_start_ts),
        "start_time_rel_s": round(req_start_ts - base_ts, 1),
        "ttfb_ms": round(ttfb_s * 1000, 1) if ttfb_s is not None else None,
        "ttft_ms": round(ttft_s * 1000, 1) if ttft_s is not None else None,
        "latency_ms": round(latency_s * 1000, 1) if latency_s is not None else None,
        "tpot_ms_per_token": round(tpot_ms, 1) if tpot_ms is not None else None,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "req_send_ms": round((req_end_ts - req_start_ts) * 1000, 1),
        "is_https": is_https,
        "stream_start_real": fmt_real_time(stream_start.ts) if stream_start else None,
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


def parse_pcap_to_entries(
    pcap_path: Path,
    self_hosted_configs: list[dict],
) -> list[dict]:
    packets = extract_packets(pcap_path)
    if not packets:
        return []
    flows = group_bi_flows(packets)
    flow_key, ai_flow = _pick_flow(flows, self_hosted_configs=self_hosted_configs)
    client_ip, server_ip = infer_direction(ai_flow)
    major, minor = classify_flow(ai_flow, client_ip=client_ip, server_ip=server_ip, self_hosted_configs=self_hosted_configs)

    chunks = split_entries(ai_flow)
    base_ts = packets[0].ts
    entries = [_build_entry(c, client_ip, server_ip, flow_key, major, minor, base_ts) for c in chunks if c]
    return [entry for entry in entries if _is_valid_entry(entry)]
