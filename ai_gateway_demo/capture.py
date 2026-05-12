from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, AsyncSniffer, wrpcap
from scapy.packet import Packet

from .db import insert_entry, list_self_hosted
from .parser import parse_pcap_to_entries

CAPTURE_PATH = Path("captures")
CAPTURE_PATH.mkdir(exist_ok=True)
DEFAULT_IDLE_TIMEOUT_SEC = 300


@dataclass
class CaptureStatus:
    running: bool = False
    interface: str = ""
    interval_sec: int = 60
    idle_timeout_sec: int = DEFAULT_IDLE_TIMEOUT_SEC
    bpf_filter: str = "tcp"
    started_at: str | None = None
    current_file: str | None = None
    last_window_started_at: str | None = None
    last_window_finished_at: str | None = None
    last_pcap: str | None = None
    last_detected: int = 0
    last_inserted: int = 0
    last_finalized_flows: int = 0
    last_finalized_packets: int = 0
    cached_flows: int = 0
    cached_packets: int = 0
    total_windows: int = 0
    total_detected: int = 0
    total_inserted: int = 0
    total_finalized_flows: int = 0
    total_finalized_packets: int = 0
    total_captured_packets: int = 0
    last_error: str | None = None
    message: str = "未启动在线监听"


@dataclass
class _CachedFlow:
    packets: list[Packet] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    close_seen: bool = False


@dataclass
class OnlineCaptureManager:
    output_dir: Path = CAPTURE_PATH
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _sniffer: AsyncSniffer | None = field(default=None, init=False)
    _status: CaptureStatus = field(default_factory=CaptureStatus, init=False)
    _flows: dict[tuple[str, int, str, int], _CachedFlow] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._sync_cache_counts_locked()
            return dict(self._status.__dict__)

    def start(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = DEFAULT_IDLE_TIMEOUT_SEC,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")

        interval_sec = max(5, int(interval_sec or 60))
        idle_timeout_sec = max(5, int(idle_timeout_sec or DEFAULT_IDLE_TIMEOUT_SEC))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._flows = {}
            self._stop_event.clear()
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                bpf_filter=bpf_filter,
                started_at=now,
                message=f"在线监听已启动：{interface}，每 {interval_sec} 秒回溯处理 FIN/RST 或空闲超过 {idle_timeout_sec} 秒的流",
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        self._stop_sniffer()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5)
        with self._lock:
            self._status.running = False
            self._status.message = "在线监听已停止"
            self._status.current_file = None
            self._sync_cache_counts_locked()
            return dict(self._status.__dict__)

    def _run_loop(self, interface: str, interval_sec: int, bpf_filter: str, idle_timeout_sec: int) -> None:
        try:
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=bpf_filter,
                store=False,
                prn=self._handle_packet,
            )
            self._sniffer.start()
            self._set_message(f"正在监听 {interface}；等待周期性回溯处理")

            while not self._stop_event.wait(timeout=interval_sec):
                self._process_ready_flows(idle_timeout_sec)

            self._process_ready_flows(idle_timeout_sec, flush_all=True)
        except Exception as exc:  # pragma: no cover - depends on local capture privileges/tooling
            with self._lock:
                self._status.last_error = str(exc)
                self._status.message = f"在线监听异常：{exc}"
        finally:
            self._stop_sniffer()
            with self._lock:
                self._status.running = False
                self._status.current_file = None
                self._sync_cache_counts_locked()
                if self._status.message.startswith("正在监听"):
                    self._status.message = "在线监听已停止"

    def _handle_packet(self, packet: Packet) -> None:
        key = _flow_key(packet)
        if key is None:
            return
        pkt_ts = float(getattr(packet, "time", time.time()))
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = _CachedFlow(first_seen=pkt_ts, last_seen=pkt_ts)
                self._flows[key] = flow
            cached_packet = packet.copy()
            cached_packet.time = pkt_ts
            flow.packets.append(cached_packet)
            flow.last_seen = pkt_ts
            flow.close_seen = flow.close_seen or _has_fin_or_rst(packet)
            self._status.total_captured_packets += 1
            self._sync_cache_counts_locked()

    def _process_ready_flows(self, idle_timeout_sec: int, flush_all: bool = False) -> None:
        now = time.time()
        window_started = datetime.now()
        ready_packets: list[Packet] = []
        ready_flow_count = 0

        with self._lock:
            ready_keys = [
                key
                for key, flow in self._flows.items()
                if flush_all or flow.close_seen or (now - flow.last_seen) >= idle_timeout_sec
            ]
            for key in ready_keys:
                flow = self._flows.pop(key)
                ready_packets.extend(flow.packets)
                ready_flow_count += 1
            self._sync_cache_counts_locked()

        if not ready_packets:
            with self._lock:
                self._status.last_window_started_at = _format_dt(window_started)
                self._status.last_window_finished_at = _now_text()
                self._status.last_detected = 0
                self._status.last_inserted = 0
                self._status.last_finalized_flows = 0
                self._status.last_finalized_packets = 0
                self._status.message = "本周期没有 FIN/RST 或 idle timeout 的完整流，继续缓存未完成报文"
            return

        file_path = self.output_dir / f"online_flows_{window_started.strftime('%Y%m%d_%H%M%S')}.pcap"
        with self._lock:
            self._status.current_file = str(file_path)
            self._status.last_window_started_at = _format_dt(window_started)
            self._status.last_error = None
            self._status.message = f"正在回溯分析 {ready_flow_count} 条已完成/超时流"

        try:
            ready_packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))
            wrpcap(str(file_path), ready_packets)
            detected, inserted = self._analyze_file(file_path)
            with self._lock:
                self._status.last_window_finished_at = _now_text()
                self._status.last_pcap = str(file_path)
                self._status.last_detected = detected
                self._status.last_inserted = inserted
                self._status.last_finalized_flows = ready_flow_count
                self._status.last_finalized_packets = len(ready_packets)
                self._status.total_windows += 1
                self._status.total_detected += detected
                self._status.total_inserted += inserted
                self._status.total_finalized_flows += ready_flow_count
                self._status.total_finalized_packets += len(ready_packets)
                self._status.current_file = None
                self._status.message = f"本周期处理 {ready_flow_count} 条流/{len(ready_packets)} 个报文：检测 {detected} 条，入库 {inserted} 条"
                self._sync_cache_counts_locked()
        except Exception as exc:  # pragma: no cover - file/parser dependent
            with self._lock:
                self._status.last_error = str(exc)
                self._status.current_file = None
                self._status.message = f"在线回溯分析异常：{exc}"

    def _analyze_file(self, file_path: Path) -> tuple[int, int]:
        if not file_path.exists() or file_path.stat().st_size == 0:
            return 0, 0
        configs = list_self_hosted()
        entries = parse_pcap_to_entries(file_path, self_hosted_configs=configs)
        inserted = sum(1 for entry in entries if insert_entry(entry))
        return len(entries), inserted

    def _stop_sniffer(self) -> None:
        sniffer = self._sniffer
        if sniffer is None:
            return
        try:
            sniffer.stop()
        except Exception:
            pass
        finally:
            self._sniffer = None

    def _set_message(self, message: str) -> None:
        with self._lock:
            self._status.message = message

    def _sync_cache_counts_locked(self) -> None:
        self._status.cached_flows = len(self._flows)
        self._status.cached_packets = sum(len(flow.packets) for flow in self._flows.values())


def _flow_key(packet: Packet) -> tuple[str, int, str, int] | None:
    if IP not in packet or TCP not in packet:
        return None
    ip = packet[IP]
    tcp = packet[TCP]
    a = (str(ip.src), int(tcp.sport))
    b = (str(ip.dst), int(tcp.dport))
    left, right = (a, b) if a <= b else (b, a)
    return left[0], left[1], right[0], right[1]


def _has_fin_or_rst(packet: Packet) -> bool:
    if TCP not in packet:
        return False
    flags = int(packet[TCP].flags)
    return bool(flags & 0x01 or flags & 0x04)


def _now_text() -> str:
    return _format_dt(datetime.now())


def _format_dt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")
