from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from scapy.all import IP, TCP, Raw, rdpcap

TOKEN_LOG_ENABLE = True
TOKEN_LOG_PATH = os.path.join("uploads", "token_calc.log")

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

MIN_GO_RUN = 10
MIN_ROUNDTRIPS = 30
RETURN_SUM_MAX = 1400
ALLOW_BAD_RET_BURSTS = 2
SEGMENT_MERGE_GAP_SEC = 2.0
GO_LEN_MAX = 200


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
    wire_len: int
    sni: str | None


def _append_token_log(line: str) -> None:
    if not TOKEN_LOG_ENABLE:
        return
    try:
        os.makedirs(os.path.dirname(TOKEN_LOG_PATH), exist_ok=True)
        with open(TOKEN_LOG_PATH, "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
    except Exception:
        pass


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


def _extract_tls_sni_reassembled(flow_packets: list[PacketMeta], max_packets: int = 8, max_bytes: int = 64 * 1024) -> str | None:
    buf = bytearray()
    taken = 0
    for p in flow_packets:
        if not p.raw:
            continue
        if not buf and (p.raw[0] != TLS_HANDSHAKE or len(p.raw) < 6):
            continue
        buf.extend(p.raw)
        taken += 1
        if len(buf) > max_bytes or taken >= max_packets:
            break
        if len(buf) >= 5:
            rec_len = int.from_bytes(buf[3:5], "big")
            if len(buf) >= 5 + rec_len:
                break
    if not buf:
        return None
    raw = bytes(buf)
    if len(raw) >= 5:
        rec_len = int.from_bytes(raw[3:5], "big")
        if 0 < rec_len <= len(raw) - 5:
            raw = raw[: 5 + rec_len]
    return _extract_tls_sni(raw)


def _tls_content_type(raw: bytes) -> int | None:
    if not raw or len(raw) < 5:
        return None
    t = raw[0]
    if t in (TLS_HANDSHAKE, TLS_APPDATA, TLS_ALERT, TLS_CCS):
        return t
    return None


def _is_tls_appdata(pkt: PacketMeta) -> bool:
    return _tls_content_type(pkt.raw) == TLS_APPDATA


def _is_https_flow(flow_packets: list[PacketMeta], client_ip: str) -> bool:
    if any(pkt.src == client_ip and pkt.sni for pkt in flow_packets):
        return True
    return any(_tls_content_type(p.raw) in (TLS_HANDSHAKE, TLS_APPDATA) for p in flow_packets)


def _is_app_payload(pkt: PacketMeta, is_https: bool) -> bool:
    if is_https:
        return _is_tls_appdata(pkt)
    return len(pkt.raw) > 0


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
                src=str(ip.src),
                dst=str(ip.dst),
                sport=int(tcp.sport),
                dport=int(tcp.dport),
                payload=decode_payload(raw_bytes),
                flow_key=f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}",
                raw=raw_bytes,
                wire_len=int(len(p)),
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


def _parse_flow_tuple(flow_key: str) -> tuple[str, int, str, int] | None:
    try:
        left, right = flow_key.split("-")
        src_ip, src_port_s = left.rsplit(":", 1)
        dst_ip, dst_port_s = right.rsplit(":", 1)
        return src_ip, int(src_port_s), dst_ip, int(dst_port_s)
    except Exception:
        return None


def _flow_tuple_from_key(flow_key: str) -> tuple[str, int, str, int]:
    t = _parse_flow_tuple(flow_key)
    if t is None:
        raise ValueError(flow_key)
    return t


def _wsw_find_go_tuple(ordered: list[PacketMeta]) -> tuple[str, int, str, int] | None:
    for p in ordered:
        if p.sni:
            t = _parse_flow_tuple(p.flow_key)
            if t:
                return t
    for p in ordered:
        t = _parse_flow_tuple(p.flow_key)
        if not t:
            continue
        sip, sport, dip, dport = t
        if sport == dport:
            continue
        return (sip, sport, dip, dport) if sport > dport else (dip, dport, sip, sport)
    return None


def infer_direction(flow_packets: list[PacketMeta], go_tuple: tuple[str, int, str, int] | None = None) -> tuple[str, str]:
    if go_tuple:
        return go_tuple[0], go_tuple[2]

    ips = sorted({p.src for p in flow_packets} | {p.dst for p in flow_packets})
    if len(ips) < 2:
        return (ips[0], ips[0]) if ips else ("", "")

    sni_senders = [p.src for p in flow_packets if p.sni]
    if sni_senders:
        client = max(set(sni_senders), key=sni_senders.count)
        server = next((ip for ip in ips if ip != client), client)
        return client, server

    byte_by_src: dict[str, int] = defaultdict(int)
    for pkt in flow_packets:
        byte_by_src[pkt.src] += len(pkt.raw)
    client = min(byte_by_src, key=byte_by_src.get)
    server = next((ip for ip in byte_by_src if ip != client), client)
    return client, server


def _collect_sni(flow_packets: list[PacketMeta]) -> str | None:
    snis = [p.sni.strip().lower() for p in flow_packets if p.sni and p.sni.strip()]
    if snis:
        return max(set(snis), key=snis.count)
    sni2 = _extract_tls_sni_reassembled(flow_packets)
    if sni2:
        return sni2
    merged = "\n".join(p.payload for p in flow_packets if p.payload)
    m = re.search(r"(?im)^(?:host|authority)\s*:\s*([^\s]+)", merged)
    if m:
        return m.group(1)[:120].lower()
    return None


def classify_flow(flow_packets: list[PacketMeta], client_ip: str, server_ip: str, server_endpoint: str, self_hosted_configs: list[dict]) -> tuple[str, str]:
    for cfg in self_hosted_configs:
        target = (cfg.get("server_ip") or "").strip()
        if not target:
            continue
        if target == server_endpoint or target == server_ip:
            return "自建AI", cfg.get("name") or target

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
    return "实验AI", words[0][:30] if words else f"exp-{server_ip}"


def _find_stream_start(
    down_app: list[PacketMeta],
    anchor_ts: float,
    *,
    gap_before_s: float = 0.35,
    lookahead_s: float = 1,
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


def _wsw_detect_hit_segments(flow_items: list[PacketMeta]) -> tuple[int, tuple[str, int, str, int] | None]:
    ordered = sorted(flow_items, key=lambda p: p.ts)
    go_tuple = _wsw_find_go_tuple(ordered)
    if not go_tuple:
        return 0, None
    ret_tuple = (go_tuple[2], go_tuple[3], go_tuple[0], go_tuple[1])

    class _Run:
        __slots__ = ("dir", "pkts", "count", "sum_len", "first_go_len", "go_len_all_same", "has_oversize_go")

        def __init__(self, d: str):
            self.dir = d
            self.pkts: list[PacketMeta] = []
            self.count = 0
            self.sum_len = 0
            self.first_go_len: int | None = None
            self.go_len_all_same = True
            self.has_oversize_go = False

        def add(self, pkt: PacketMeta, pkt_len: int) -> None:
            self.pkts.append(pkt)
            self.count += 1
            self.sum_len += pkt_len
            if self.dir == "G":
                if self.first_go_len is None:
                    self.first_go_len = pkt_len
                elif pkt_len != self.first_go_len:
                    self.go_len_all_same = False
                if pkt_len >= GO_LEN_MAX:
                    self.has_oversize_go = True

    runs: list[_Run] = []
    cur: _Run | None = None

    for pkt in ordered:
        try:
            t = _flow_tuple_from_key(pkt.flow_key)
        except Exception:
            t = None
        plen = int(pkt.wire_len) if pkt.wire_len is not None else 0

        if t == go_tuple:
            d = "G"
        elif t == ret_tuple:
            d = "R"
        else:
            d = "O"

        if cur is None or d != cur.dir:
            cur = _Run(d)
            runs.append(cur)
        cur.add(pkt, plen)

    def _is_valid_go_run(r: _Run) -> bool:
        return (
            r.dir == "G"
            and (not r.has_oversize_go)
            and r.go_len_all_same
            and (r.first_go_len is not None)
            and (r.first_go_len < GO_LEN_MAX)
        )

    hit_segments = 0
    in_seg = False
    seg_intervals = 0
    seg_go_packets = 0

    def _finalize_segment() -> None:
        nonlocal hit_segments, in_seg, seg_intervals, seg_go_packets
        if in_seg and seg_go_packets >= MIN_GO_RUN and seg_intervals >= MIN_ROUNDTRIPS:
            hit_segments += 1
        in_seg = False
        seg_intervals = 0
        seg_go_packets = 0

    bad_streak = 0
    last_good_end_ts: float | None = None

    for i in range(1, len(runs) - 1):
        mid = runs[i]

        if mid.dir == "O":
            _finalize_segment()
            bad_streak = 0
            last_good_end_ts = None
            continue
        if mid.dir != "R":
            continue

        left = runs[i - 1]
        right = runs[i + 1]
        if left.dir != "G" or right.dir != "G":
            if in_seg:
                _finalize_segment()
            bad_streak = 0
            last_good_end_ts = None
            continue

        if (not _is_valid_go_run(left)) or (not _is_valid_go_run(right)):
            if in_seg:
                _finalize_segment()
            bad_streak = 0
            last_good_end_ts = None
            continue

        if in_seg and last_good_end_ts is not None:
            gap_no_ret = float(left.pkts[0].ts) - float(last_good_end_ts)
            if gap_no_ret > SEGMENT_MERGE_GAP_SEC:
                _finalize_segment()
                bad_streak = 0
                last_good_end_ts = None

        if mid.sum_len > RETURN_SUM_MAX:
            if in_seg:
                bad_streak += 1
                if bad_streak > ALLOW_BAD_RET_BURSTS:
                    _finalize_segment()
                    bad_streak = 0
                    last_good_end_ts = None
            continue

        bad_streak = 0
        seg_intervals += 1
        if not in_seg:
            in_seg = True
            seg_go_packets = left.count + right.count
        else:
            seg_go_packets += right.count

        last_good_end_ts = float(right.pkts[-1].ts)

    _finalize_segment()
    return hit_segments, go_tuple


def _wsw_extract_hit_segments(flow_items: list[PacketMeta]) -> tuple[list[list[PacketMeta]], tuple[str, int, str, int] | None]:
    ordered = sorted(flow_items, key=lambda p: p.ts)
    go_tuple = _wsw_find_go_tuple(ordered)
    if not go_tuple:
        return [], None
    ret_tuple = (go_tuple[2], go_tuple[3], go_tuple[0], go_tuple[1])

    class _Run:
        __slots__ = ("dir", "pkts", "count", "sum_len", "first_go_len", "go_len_all_same", "has_oversize_go")

        def __init__(self, d: str):
            self.dir = d
            self.pkts: list[PacketMeta] = []
            self.count = 0
            self.sum_len = 0
            self.first_go_len: int | None = None
            self.go_len_all_same = True
            self.has_oversize_go = False

        def add(self, pkt: PacketMeta, pkt_len: int) -> None:
            self.pkts.append(pkt)
            self.count += 1
            self.sum_len += pkt_len
            if self.dir == "G":
                if self.first_go_len is None:
                    self.first_go_len = pkt_len
                elif pkt_len != self.first_go_len:
                    self.go_len_all_same = False
                if pkt_len >= GO_LEN_MAX:
                    self.has_oversize_go = True

    runs: list[_Run] = []
    cur: _Run | None = None
    for pkt in ordered:
        try:
            t = _flow_tuple_from_key(pkt.flow_key)
        except Exception:
            t = None
        plen = int(pkt.wire_len) if pkt.wire_len is not None else 0
        if t == go_tuple:
            d = "G"
        elif t == ret_tuple:
            d = "R"
        else:
            d = "O"
        if cur is None or d != cur.dir:
            cur = _Run(d)
            runs.append(cur)
        cur.add(pkt, plen)

    def _is_valid_go_run(r: _Run) -> bool:
        return (
            r.dir == "G"
            and (not r.has_oversize_go)
            and r.go_len_all_same
            and (r.first_go_len is not None)
            and (r.first_go_len < GO_LEN_MAX)
        )

    segments: list[list[PacketMeta]] = []
    in_seg = False
    seg_start_run = -1
    seg_end_run = -1
    seg_intervals = 0
    seg_go_packets = 0

    def _finalize() -> None:
        nonlocal in_seg, seg_start_run, seg_end_run, seg_intervals, seg_go_packets
        if in_seg and seg_go_packets >= MIN_GO_RUN and seg_intervals >= MIN_ROUNDTRIPS:
            pkts: list[PacketMeta] = []
            for r in runs[seg_start_run : seg_end_run + 1]:
                pkts.extend(r.pkts)
            pkts.sort(key=lambda p: p.ts)
            segments.append(pkts)
        in_seg = False
        seg_start_run = -1
        seg_end_run = -1
        seg_intervals = 0
        seg_go_packets = 0

    bad_streak = 0
    last_good_end_ts: float | None = None

    for i in range(1, len(runs) - 1):
        mid = runs[i]
        if mid.dir == "O":
            _finalize()
            bad_streak = 0
            last_good_end_ts = None
            continue
        if mid.dir != "R":
            continue

        left = runs[i - 1]
        right = runs[i + 1]
        if left.dir != "G" or right.dir != "G":
            if in_seg:
                _finalize()
            bad_streak = 0
            last_good_end_ts = None
            continue

        if (not _is_valid_go_run(left)) or (not _is_valid_go_run(right)):
            if in_seg:
                _finalize()
            bad_streak = 0
            last_good_end_ts = None
            continue

        if in_seg and last_good_end_ts is not None:
            gap_no_ret = float(left.pkts[0].ts) - float(last_good_end_ts)
            if gap_no_ret > SEGMENT_MERGE_GAP_SEC:
                _finalize()
                bad_streak = 0
                last_good_end_ts = None

        if mid.sum_len > RETURN_SUM_MAX:
            if in_seg:
                bad_streak += 1
                if bad_streak > ALLOW_BAD_RET_BURSTS:
                    _finalize()
                    bad_streak = 0
                    last_good_end_ts = None
            continue

        bad_streak = 0
        seg_intervals += 1
        if not in_seg:
            in_seg = True
            seg_start_run = i - 1
            seg_end_run = i + 1
            seg_go_packets = left.count + right.count
        else:
            seg_end_run = i + 1
            seg_go_packets += right.count

        last_good_end_ts = float(right.pkts[-1].ts)

    _finalize()
    return segments, go_tuple


def _merge_adjacent_segments_by_gap(segments: list[list[PacketMeta]], flow_items: list[PacketMeta], gap_sec: float = 2.0) -> list[list[PacketMeta]]:
    if not segments:
        return []
    ordered_all = sorted(flow_items, key=lambda p: p.ts)
    segs = [sorted(seg, key=lambda p: p.ts) for seg in segments if seg]
    if not segs:
        return []
    segs.sort(key=lambda seg: seg[0].ts)

    merged: list[list[PacketMeta]] = []
    cur = segs[0]
    for nxt in segs[1:]:
        cur_end = cur[-1].ts
        nxt_start = nxt[0].ts
        if (nxt_start - cur_end) < gap_sec:
            gap_pkts = [p for p in ordered_all if cur_end < p.ts < nxt_start]
            cur = sorted(cur + gap_pkts + nxt, key=lambda p: p.ts)
        else:
            merged.append(cur)
            cur = nxt
    merged.append(cur)
    return merged


def _pick_flows(flows: dict[str, list[PacketMeta]]) -> list[tuple[str, list[PacketMeta], tuple[str, int, str, int] | None]]:
    selected: list[tuple[str, list[PacketMeta], tuple[str, int, str, int] | None]] = []
    for key, items in flows.items():
        hit_cnt, go_tuple = _wsw_detect_hit_segments(items)
        if hit_cnt > 0:
            selected.append((key, items, go_tuple))

    def _bytes(pkts: list[PacketMeta]) -> int:
        return sum(len(p.raw or b"") for p in pkts)

    selected.sort(key=lambda x: (_wsw_detect_hit_segments(x[1])[0], _bytes(x[1])), reverse=True)
    return selected


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

    ttfb_s = max((first_down_after_start.ts - req_start_ts), 0.0) if first_down_after_start else None

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

    down_after_start = [p for p in down_app if p.ts >= req_start_ts]
    last_down = down_after_start[-1] if down_after_start else (down_app[-1] if down_app else ordered[-1])
    latency_s = max((last_down.ts - req_start_ts), 0.0) if last_down else None

    input_tokens = sum(count_tokens(p.payload) for p in ordered if p.src == client_ip)
    output_tokens = sum(count_tokens(p.payload) for p in ordered if p.src == server_ip and p.ts >= req_start_ts)

    if latency_s is not None and ttft_s is not None and output_tokens > 0:
        tpot_ms = max((latency_s - ttft_s) * 1000, 0) / output_tokens
    else:
        tpot_ms = None

    _append_token_log(f"flow={flow_key} req_send_ms={(req_end_ts-req_start_ts)*1000:.3f} out_tokens={output_tokens}")

    return {
        "category_major": major,
        "category_minor": minor,
        "flow_key": flow_key,
        "start_time_real": fmt_real_time(req_start_ts),
        "end_time_real": fmt_real_time(last_down.ts if last_down else req_start_ts),
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
    return True




def _infer_server_endpoint(flow_packets: list[PacketMeta], client_ip: str, server_ip: str, go_tuple: tuple[str, int, str, int] | None) -> str:
    if go_tuple:
        return f"{go_tuple[2]}:{go_tuple[3]}"
    c2s = next((p for p in flow_packets if p.src == client_ip and p.dst == server_ip), None)
    if c2s is not None:
        return f"{server_ip}:{c2s.dport}"
    s2c = next((p for p in flow_packets if p.src == server_ip and p.dst == client_ip), None)
    if s2c is not None:
        return f"{server_ip}:{s2c.sport}"
    return server_ip


def parse_pcap_to_entries(pcap_path: Path, self_hosted_configs: list[dict]) -> list[dict]:
    packets = extract_packets(pcap_path)
    if not packets:
        return []

    flows = group_bi_flows(packets)
    picked = _pick_flows(flows)
    if not picked:
        return []

    base_ts = packets[0].ts
    out_entries: list[dict] = []

    for flow_key, flow_packets, go_tuple in picked:
        segments, go_tuple2 = _wsw_extract_hit_segments(flow_packets)
        go_use = go_tuple2 or go_tuple
        segments = _merge_adjacent_segments_by_gap(segments, flow_packets, gap_sec=SEGMENT_MERGE_GAP_SEC)

        client_ip, server_ip = infer_direction(flow_packets, go_tuple=go_use)
        server_endpoint = _infer_server_endpoint(flow_packets, client_ip, server_ip, go_use)
        major, minor = classify_flow(flow_packets, client_ip, server_ip, server_endpoint, self_hosted_configs)
        if major == "实验AI":
            minor = _collect_sni(flow_packets) or minor

        for seg_pkts in segments:
            if not seg_pkts:
                continue
            c_ip, s_ip = infer_direction(seg_pkts, go_tuple=go_use)
            e = _build_entry(seg_pkts, c_ip, s_ip, flow_key, major, minor, base_ts)
            if _is_valid_entry(e):
                out_entries.append(e)

    out_entries.sort(key=lambda x: x.get("start_time_rel_s", 0.0))
    return out_entries
