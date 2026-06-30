from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, PcapReader
from scapy.utils import RawPcapReader

AI_APP_SNI_RULES: dict[str, tuple[str, ...]] = {
    "\u8c46\u5305": (
        "doubao.com",
        "doubao.cn",
        "dola.com",
        "ciciai.com",
        "coze.com",
        "coze.cn",
        "volcengine.com",
        "volcengineapi.com",
        "bytepluses.com",
        "ark.cn-beijing.volces.com",
        "ark.cn-beijing.volcengineapi.com",
        "maas-api.ml-platform-cn-beijing.volces.com",
        "seed.bytedance.com",
    ),
    "\u5343\u95ee": (
        "qianwen.com",
        "qwen.ai",
        "chat.qwen.ai",
        "chat2.qianwen.com",
        "tongyi.com",
        "tongyi.aliyun.com",
        "dashscope.aliyuncs.com",
        "dashscope-intl.aliyuncs.com",
        "bailian.aliyun.com",
        "bailian.console.aliyun.com",
    ),
    "DeepSeek": (
        "deepseek.com",
        "chat.deepseek.com",
        "api.deepseek.com",
        "platform.deepseek.com",
        "api-docs.deepseek.com",
        "cdn.deepseek.com",
        "download.deepseek.com",
        "status.deepseek.com",
    ),
    "ChatGPT": (
        "chatgpt.com",
        "ws.chatgpt.com",
        "chat.openai.com",
        "android.chat.openai.com",
        "desktop.chat.openai.com",
        "ios.chat.openai.com",
        "tcr9i.chat.openai.com",
        "openai.com",
        "api.openai.com",
        "auth.openai.com",
        "auth0.openai.com",
        "setup.auth.openai.com",
        "platform.openai.com",
        "cdn.openai.com",
        "openaimerge.com",
        "cdn.openaimerge.com",
        "oaistatic.com",
        "cdn.oaistatic.com",
        "persistent.oaistatic.com",
        "oaiusercontent.com",
        "files.oaiusercontent.com",
        "oaistatsig.com",
        "videos.openai.com",
        "openaicom.imgix.net",
        "oaidalleapiprodscus.blob.core.windows.net",
        "ct.sendgrid.net",
        "intercom.io",
        "intercomcdn.com",
        "js.intercomcdn.com",
        "cdn.workos.com",
        "forwarder.workos.com",
        "setup.workos.com",
        "images.workoscdn.com",
        "workos.imgix.net",
        "challenges.cloudflare.com",
        "humb.apple.com",
        "js.stripe.com",
        "o207216.ingest.sentry.io",
        "o33249.ingest.sentry.io",
        "rum.browser-intake-datadoghq.com",
    ),
}

COMMON_SERVER_PORTS = {80, 443, 8080, 8443, 9443}
TLS_HANDSHAKE = 0x16


@dataclass
class TrafficPacket:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes
    wire_len: int

    @property
    def src_endpoint(self) -> str:
        return f"{self.src}:{self.sport}"

    @property
    def dst_endpoint(self) -> str:
        return f"{self.dst}:{self.dport}"


def analyze_ai_traffic_pcap(
    pcap_path: Path,
    source: str = "unknown",
    flow_context: dict[str, dict[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    packets = _extract_packets(pcap_path)
    summary = {
        "pcap_path": str(pcap_path),
        "window_start_time": _format_ts(min((p.ts for p in packets), default=None)),
        "window_end_time": _format_ts(max((p.ts for p in packets), default=None)),
        "uplink_total_bytes": 0,
        "downlink_total_bytes": 0,
        "uplink_ai_bytes": 0,
        "downlink_ai_bytes": 0,
    }
    if not packets:
        return [], summary, []

    flows = _group_flows(packets)
    records: list[dict[str, Any]] = []
    rate_buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    for canonical_key, flow_packets in flows.items():
        ordered = sorted(flow_packets, key=lambda p: p.ts)
        endpoints = _flow_endpoints(canonical_key)
        if len(endpoints) != 2:
            continue

        sni, client_endpoint = _detect_flow_sni_and_client(ordered)
        app = _app_for_sni(sni)
        if app and flow_context is not None:
            flow_context[canonical_key] = {
                "app": app,
                "sni": sni or "",
                "client_endpoint": client_endpoint or "",
            }
        if not app and flow_context is not None:
            context = flow_context.get(canonical_key) or {}
            app = context.get("app") or None
            sni = context.get("sni") or sni
            client_endpoint = context.get("client_endpoint") or client_endpoint
        user_endpoint, server_endpoint = _infer_direction(endpoints, client_endpoint)
        uplink, downlink = _directional_bytes(ordered, user_endpoint)
        summary["uplink_total_bytes"] += uplink
        summary["downlink_total_bytes"] += downlink

        if not app:
            continue

        user_ip, user_port = _split_endpoint(user_endpoint)
        server_ip, server_port = _split_endpoint(server_endpoint)
        start_ts = ordered[0].ts
        end_ts = ordered[-1].ts
        duration_sec = max(0.0, end_ts - start_ts)
        summary["uplink_ai_bytes"] += uplink
        summary["downlink_ai_bytes"] += downlink
        _add_rate_buckets(rate_buckets, app, user_ip, ordered, user_endpoint)
        records.append(
            {
                "source": source,
                "pcap_path": str(pcap_path),
                "app": app,
                "sni": sni or "",
                "protocol": "TCP",
                "flow_key": f"{user_endpoint}-{server_endpoint}",
                "user_ip": user_ip,
                "user_port": user_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "uplink_bytes": uplink,
                "downlink_bytes": downlink,
                "total_bytes": uplink + downlink,
                "peak_bps": 0,
                "duration_sec": duration_sec,
                "start_time_real": _format_ts(start_ts) or "",
                "end_time_real": _format_ts(end_ts) or "",
            }
        )
    return records, summary, list(rate_buckets.values())


def summarize_parser_detected_ai_traffic(pcap_path: Path, entries: list[dict[str, Any]]) -> dict[str, int]:
    packets = _extract_packets(pcap_path)
    if not packets or not entries:
        return {"uplink_ai_bytes": 0, "downlink_ai_bytes": 0}

    flows = _group_flows(packets)
    detected: set[tuple[str, str]] = set()
    for entry in entries:
        flow_key = str(entry.get("flow_key") or "")
        parsed = _parse_entry_flow_key(flow_key)
        if not parsed:
            continue
        user_endpoint, server_endpoint = parsed
        detected.add((_canonical_key(user_endpoint, server_endpoint), user_endpoint))

    uplink = 0
    downlink = 0
    for canonical_key, user_endpoint in detected:
        flow_packets = flows.get(canonical_key) or []
        up, down = _directional_bytes(flow_packets, user_endpoint)
        uplink += up
        downlink += down
    return {"uplink_ai_bytes": uplink, "downlink_ai_bytes": downlink}


def _extract_packets(pcap_path: Path) -> list[TrafficPacket]:
    raw_packets = _extract_packets_raw(pcap_path)
    if raw_packets is not None:
        return raw_packets
    return _extract_packets_scapy(pcap_path)


def _extract_packets_raw(pcap_path: Path) -> list[TrafficPacket] | None:
    try:
        reader = RawPcapReader(str(pcap_path))
    except Exception:
        return None
    result: list[TrafficPacket] = []
    try:
        if getattr(reader, "linktype", None) != 1:
            return None
        for raw_packet, meta in reader:
            parsed = _extract_ipv4_tcp_meta_from_ethernet(raw_packet)
            if parsed is None:
                continue
            src, sport, dst, dport, payload = parsed
            cap_len = int(getattr(meta, "caplen", len(raw_packet)) or len(raw_packet))
            wire_len = int(getattr(meta, "wirelen", cap_len) or cap_len)
            result.append(
                TrafficPacket(
                    ts=_meta_ts(meta),
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    payload=payload,
                    wire_len=wire_len,
                )
            )
    finally:
        try:
            reader.close()
        except Exception:
            pass
    return sorted(result, key=lambda p: p.ts)


def _extract_packets_scapy(pcap_path: Path) -> list[TrafficPacket]:
    result: list[TrafficPacket] = []
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP not in packet or TCP not in packet:
                continue
            ip = packet[IP]
            tcp = packet[TCP]
            payload = bytes(tcp.payload) if bytes(tcp.payload) else b""
            packet_len = int(getattr(packet, "wirelen", len(packet)) or len(packet))
            result.append(
                TrafficPacket(
                    ts=float(packet.time),
                    src=str(ip.src),
                    dst=str(ip.dst),
                    sport=int(tcp.sport),
                    dport=int(tcp.dport),
                    payload=payload,
                    wire_len=packet_len,
                )
            )
    return sorted(result, key=lambda p: p.ts)


def _meta_ts(meta: Any) -> float:
    sec = float(getattr(meta, "sec", 0) or 0)
    usec = float(getattr(meta, "usec", 0) or 0)
    if hasattr(meta, "nsec"):
        return sec + float(getattr(meta, "nsec", 0) or 0) / 1_000_000_000
    return sec + usec / 1_000_000


def _extract_ipv4_tcp_meta_from_ethernet(raw_packet: bytes) -> tuple[str, int, str, int, bytes] | None:
    if len(raw_packet) < 14:
        return None
    eth_type = int.from_bytes(raw_packet[12:14], "big")
    ip_offset = 14
    while eth_type in (0x8100, 0x88A8, 0x9100):
        if len(raw_packet) < ip_offset + 4:
            return None
        eth_type = int.from_bytes(raw_packet[ip_offset + 2 : ip_offset + 4], "big")
        ip_offset += 4
    if eth_type != 0x0800 or len(raw_packet) < ip_offset + 20:
        return None
    version_ihl = raw_packet[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(raw_packet) < ip_offset + ihl:
        return None
    if raw_packet[ip_offset + 9] != 6:
        return None
    total_len = int.from_bytes(raw_packet[ip_offset + 2 : ip_offset + 4], "big")
    fragment = int.from_bytes(raw_packet[ip_offset + 6 : ip_offset + 8], "big")
    if fragment & 0x1FFF:
        return None
    tcp_offset = ip_offset + ihl
    if len(raw_packet) < tcp_offset + 20:
        return None
    data_offset = (raw_packet[tcp_offset + 12] >> 4) * 4
    if data_offset < 20:
        return None
    ip_end = min(len(raw_packet), ip_offset + total_len) if total_len else len(raw_packet)
    payload_offset = tcp_offset + data_offset
    if payload_offset > ip_end:
        return None
    src = ".".join(str(part) for part in raw_packet[ip_offset + 12 : ip_offset + 16])
    dst = ".".join(str(part) for part in raw_packet[ip_offset + 16 : ip_offset + 20])
    sport = int.from_bytes(raw_packet[tcp_offset : tcp_offset + 2], "big")
    dport = int.from_bytes(raw_packet[tcp_offset + 2 : tcp_offset + 4], "big")
    return src, sport, dst, dport, bytes(raw_packet[payload_offset:ip_end])


def _group_flows(packets: list[TrafficPacket]) -> dict[str, list[TrafficPacket]]:
    groups: dict[str, list[TrafficPacket]] = defaultdict(list)
    for packet in packets:
        side1 = f"{packet.src}:{packet.sport}"
        side2 = f"{packet.dst}:{packet.dport}"
        key = _canonical_key(side1, side2)
        groups[key].append(packet)
    return groups


def _canonical_key(endpoint_a: str, endpoint_b: str) -> str:
    left_ip, left_port = _split_endpoint(endpoint_a)
    right_ip, right_port = _split_endpoint(endpoint_b)
    left = (left_ip, str(left_port))
    right = (right_ip, str(right_port))
    return f"{endpoint_a}-{endpoint_b}" if left <= right else f"{endpoint_b}-{endpoint_a}"


def _parse_entry_flow_key(flow_key: str) -> tuple[str, str] | None:
    if "-" not in flow_key:
        return None
    user_endpoint, server_endpoint = flow_key.split("-", 1)
    if "?" in user_endpoint or "?" in server_endpoint:
        return None
    user_ip, user_port = _split_endpoint(user_endpoint)
    server_ip, server_port = _split_endpoint(server_endpoint)
    if not user_ip or not server_ip or user_port <= 0 or server_port <= 0:
        return None
    return f"{user_ip}:{user_port}", f"{server_ip}:{server_port}"


def _flow_endpoints(flow_key: str) -> list[str]:
    if "-" not in flow_key:
        return []
    left, right = flow_key.split("-", 1)
    return [left, right]


def _detect_flow_sni_and_client(packets: list[TrafficPacket]) -> tuple[str | None, str | None]:
    by_source: dict[str, list[TrafficPacket]] = defaultdict(list)
    for packet in packets:
        by_source[packet.src_endpoint].append(packet)

    for endpoint, endpoint_packets in by_source.items():
        sni = _extract_sni_from_endpoint_packets(endpoint_packets)
        if sni:
            return sni, endpoint
    return None, None


def _extract_sni_from_endpoint_packets(packets: list[TrafficPacket], max_packets: int = 8, max_bytes: int = 64 * 1024) -> str | None:
    buf = bytearray()
    taken = 0
    for packet in sorted(packets, key=lambda p: p.ts):
        if not packet.payload:
            continue
        direct = _extract_tls_sni(packet.payload)
        if direct:
            return direct
        if not buf and (packet.payload[0] != TLS_HANDSHAKE or len(packet.payload) < 6):
            continue
        buf.extend(packet.payload)
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
                    return ext_data[pos : pos + name_len].decode("utf-8", errors="ignore").lower().rstrip(".")
                pos += name_len
    except Exception:
        return None
    return None


def _infer_direction(endpoints: list[str], client_endpoint: str | None) -> tuple[str, str]:
    if client_endpoint and client_endpoint in endpoints:
        server_endpoint = endpoints[0] if endpoints[1] == client_endpoint else endpoints[1]
        return client_endpoint, server_endpoint
    left, right = endpoints
    left_port = _split_endpoint(left)[1]
    right_port = _split_endpoint(right)[1]
    if left_port in COMMON_SERVER_PORTS and right_port not in COMMON_SERVER_PORTS:
        return right, left
    if right_port in COMMON_SERVER_PORTS and left_port not in COMMON_SERVER_PORTS:
        return left, right
    if left_port < right_port:
        return right, left
    return left, right


def _directional_bytes(packets: list[TrafficPacket], user_endpoint: str) -> tuple[int, int]:
    uplink = 0
    downlink = 0
    for packet in packets:
        if packet.src_endpoint == user_endpoint:
            uplink += int(packet.wire_len or 0)
        else:
            downlink += int(packet.wire_len or 0)
    return uplink, downlink


def _add_rate_buckets(
    buckets: dict[tuple[str, str, str], dict[str, Any]],
    app: str,
    user_ip: str,
    packets: list[TrafficPacket],
    user_endpoint: str,
) -> None:
    for packet in packets:
        label = _format_ts(int(packet.ts)) or ""
        if not label:
            continue
        key = (label, app, user_ip)
        bucket = buckets.setdefault(
            key,
            {
                "bucket_time": label,
                "app": app,
                "user_ip": user_ip,
                "uplink_bytes": 0,
                "downlink_bytes": 0,
            },
        )
        if packet.src_endpoint == user_endpoint:
            bucket["uplink_bytes"] += int(packet.wire_len or 0)
        else:
            bucket["downlink_bytes"] += int(packet.wire_len or 0)


def _app_for_sni(sni: str | None) -> str | None:
    value = (sni or "").strip().lower().rstrip(".")
    if not value:
        return None
    for app, domains in AI_APP_SNI_RULES.items():
        for domain in domains:
            normalized = domain.lower().rstrip(".")
            if value == normalized or value.endswith(f".{normalized}"):
                return app
    return None


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    if ":" not in endpoint:
        return endpoint.strip(), 0
    host, port = endpoint.rsplit(":", 1)
    try:
        return host.strip(), int(port)
    except ValueError:
        return host.strip(), 0


def _format_ts(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
