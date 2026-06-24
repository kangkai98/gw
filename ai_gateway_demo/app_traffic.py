from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, Raw, PcapReader

from .db import upsert_app_flow_stat

AI_APP_SNI_RULES: dict[str, tuple[str, ...]] = {
    "千问API": ("dashscope.aliyuncs.com",),
    "千问": ("chat2.qianwen.com",),
    "DeepSeek API": ("api.deepseek.com",),
    "DeepSeek": ("chat.deepseek.com",),
    "智谱API": ("open.bigmodel.cn",),
    "智谱": ("chatglm.cn",),
    "豆包": ("www.doubao.com",),
    "ChatGPT": ("chatgpt.com",),
    "Gemini": ("gemini.google.com",),
    "Claude": ("claude.ai",),
    "Kimi": ("www.kimi.com",),
    "元宝": ("yuanbao.tencent.com",),
    "小微助手": ("api.assistant.welink.huawei.com",),
}


@dataclass
class AppPacket:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    flags: int
    wire_len: int
    payload: bytes


@dataclass
class AppFlowAccumulator:
    flow_uid: str
    app_name: str
    sni: str
    flow_key: str
    client_endpoint: str
    server_endpoint: str
    start_ts: float
    end_ts: float
    uplink_bytes: int = 0
    downlink_bytes: int = 0
    buckets: dict[int, int] = field(default_factory=dict)
    closed: bool = False


_lock = threading.Lock()
_active_flows: dict[str, AppFlowAccumulator] = {}


def reset_app_traffic_observer() -> None:
    with _lock:
        _active_flows.clear()


def flush_app_traffic_observer() -> None:
    with _lock:
        for key in list(_active_flows.keys()):
            _persist_flow_locked(key)
        _active_flows.clear()


def observe_pcap_app_traffic(pcap_path: Path) -> None:
    grouped: dict[str, list[AppPacket]] = defaultdict(list)
    try:
        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                if IP not in packet or TCP not in packet:
                    continue
                ip = packet[IP]
                tcp = packet[TCP]
                raw_payload = bytes(packet[Raw].load) if Raw in packet else b""
                item = AppPacket(
                    ts=float(packet.time),
                    src=str(ip.src),
                    sport=int(tcp.sport),
                    dst=str(ip.dst),
                    dport=int(tcp.dport),
                    flags=int(tcp.flags),
                    wire_len=int(getattr(packet, "wirelen", len(bytes(packet))) or len(bytes(packet))),
                    payload=raw_payload,
                )
                grouped[_canonical_flow_key(item.src, item.sport, item.dst, item.dport)].append(item)
    except FileNotFoundError:
        return

    with _lock:
        for flow_key, packets in grouped.items():
            if not packets:
                continue
            active = _active_flows.get(flow_key)
            if active is None:
                active = _build_flow_from_sni(flow_key, packets)
                if active is None:
                    continue
                _active_flows[flow_key] = active
            _apply_packets_to_flow(active, packets)
            _persist_flow_locked(flow_key)
            if active.closed:
                _active_flows.pop(flow_key, None)


def _build_flow_from_sni(flow_key: str, packets: list[AppPacket]) -> AppFlowAccumulator | None:
    for packet in packets:
        sni = _extract_tls_sni(packet.payload)
        app_name = _app_name_for_sni(sni)
        if not app_name:
            continue
        return AppFlowAccumulator(
            flow_uid=f"{_format_ts(packet.ts)}|{flow_key}",
            app_name=app_name,
            sni=(sni or "").strip().lower().rstrip("."),
            flow_key=flow_key,
            client_endpoint=f"{packet.src}:{packet.sport}",
            server_endpoint=f"{packet.dst}:{packet.dport}",
            start_ts=packet.ts,
            end_ts=packet.ts,
        )
    return None


def _apply_packets_to_flow(flow: AppFlowAccumulator, packets: list[AppPacket]) -> None:
    for packet in packets:
        flow.start_ts = min(flow.start_ts, packet.ts)
        flow.end_ts = max(flow.end_ts, packet.ts)
        src_endpoint = f"{packet.src}:{packet.sport}"
        dst_endpoint = f"{packet.dst}:{packet.dport}"
        if src_endpoint == flow.client_endpoint or dst_endpoint == flow.server_endpoint:
            flow.uplink_bytes += packet.wire_len
        else:
            flow.downlink_bytes += packet.wire_len
        bucket = int(packet.ts)
        flow.buckets[bucket] = flow.buckets.get(bucket, 0) + packet.wire_len
        if packet.flags & 0x05:
            flow.closed = True


def _persist_flow_locked(flow_key: str) -> None:
    flow = _active_flows.get(flow_key)
    if flow is None:
        return
    upsert_app_flow_stat(
        {
            "app_name": flow.app_name,
            "flow_uid": flow.flow_uid,
            "sni": flow.sni,
            "flow_key": flow.flow_key,
            "protocol": "TCP",
            "client_endpoint": flow.client_endpoint,
            "server_endpoint": flow.server_endpoint,
            "start_time_real": _format_ts(flow.start_ts),
            "end_time_real": _format_ts(flow.end_ts),
            "duration_sec": max(0.0, flow.end_ts - flow.start_ts),
            "uplink_bytes": flow.uplink_bytes,
            "downlink_bytes": flow.downlink_bytes,
            "peak_bps": float(max(flow.buckets.values(), default=0) * 8),
        }
    )


def _app_name_for_sni(sni: str | None) -> str | None:
    value = (sni or "").strip().lower().rstrip(".")
    if not value:
        return None
    for app_name, domains in AI_APP_SNI_RULES.items():
        if any(value == domain.lower().rstrip(".") for domain in domains):
            return app_name
    return None


def _extract_tls_sni(data: bytes) -> str | None:
    if len(data) < 5 or data[0] != 0x16:
        return None
    pos = 5
    if pos + 4 > len(data) or data[pos] != 0x01:
        return None
    hs_len = int.from_bytes(data[pos + 1 : pos + 4], "big")
    pos += 4
    end = min(len(data), pos + hs_len)
    if pos + 34 > end:
        return None
    pos += 34
    if pos >= end:
        return None
    session_len = data[pos]
    pos += 1 + session_len
    if pos + 2 > end:
        return None
    cipher_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2 + cipher_len
    if pos >= end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > end:
        return None
    ext_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    ext_end = min(end, pos + ext_len)
    while pos + 4 <= ext_end:
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        ext_data_end = pos + ext_size
        if ext_data_end > ext_end:
            return None
        if ext_type == 0:
            if pos + 2 > ext_data_end:
                return None
            name_list_len = int.from_bytes(data[pos : pos + 2], "big")
            name_pos = pos + 2
            name_end = min(ext_data_end, name_pos + name_list_len)
            while name_pos + 3 <= name_end:
                name_type = data[name_pos]
                name_len = int.from_bytes(data[name_pos + 1 : name_pos + 3], "big")
                name_pos += 3
                if name_pos + name_len > name_end:
                    return None
                if name_type == 0:
                    try:
                        return data[name_pos : name_pos + name_len].decode("idna").lower()
                    except Exception:
                        return None
                name_pos += name_len
        pos = ext_data_end
    return None


def _canonical_flow_key(src: str, sport: int, dst: str, dport: int) -> str:
    left = (src, str(sport))
    right = (dst, str(dport))
    side1 = f"{left[0]}:{left[1]}"
    side2 = f"{right[0]}:{right[1]}"
    return f"{side1}-{side2}" if left <= right else f"{side2}-{side1}"


def _format_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
