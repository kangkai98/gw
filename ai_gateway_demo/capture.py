from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, rdpcap, wrpcap
from scapy.packet import Packet

from .db import insert_entry, list_self_hosted
from .parser import parse_pcap_to_entries

CAPTURE_PATH = Path("captures")
CAPTURE_PATH.mkdir(exist_ok=True)
DEFAULT_IDLE_TIMEOUT_SEC = 300
FlowKey = tuple[str, int, str, int]


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
    last_ready_pcap: str | None = None
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
    last_error: str | None = None
    message: str = "未启动在线监听"


@dataclass
class _CachedFlow:
    packets: list[Packet] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    close_seen: bool = False


@dataclass
class _ProcessResult:
    detected: int = 0
    inserted: int = 0
    finalized_flows: int = 0
    finalized_packets: int = 0
    ready_pcap: str | None = None


@dataclass
class OnlineCaptureManager:
    output_dir: Path = CAPTURE_PATH
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _status: CaptureStatus = field(default_factory=CaptureStatus, init=False)
    _flows: dict[FlowKey, _CachedFlow] = field(default_factory=dict, init=False)

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
        if shutil.which("tcpdump") is None:
            raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        idle_timeout_sec = max(5, int(idle_timeout_sec or DEFAULT_IDLE_TIMEOUT_SEC))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._flows = {}
            self._stop_event.clear()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                bpf_filter=bpf_filter,
                started_at=_now_text(),
                message=f"在线监听已启动：{interface}，每 {interval_sec} 秒读取窗口并处理 FIN/RST 或 idle 超过 {idle_timeout_sec} 秒的流",
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
        proc = self._proc
        if proc and proc.poll() is None:
            _terminate_process(proc)
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
        while not self._stop_event.is_set():
            window_started = datetime.now()
            file_path = self.output_dir / f"online_{window_started.strftime('%Y%m%d_%H%M%S')}.pcap"
            with self._lock:
                self._status.current_file = str(file_path)
                self._status.last_window_started_at = _format_dt(window_started)
                self._status.last_error = None
                self._status.message = f"正在采集窗口：{file_path.name}"

            try:
                self._capture_one_window(interface, interval_sec, bpf_filter, file_path)
                result = self._ingest_and_process_window(
                    file_path,
                    idle_timeout_sec,
                    flush_all=self._stop_event.is_set(),
                    window_started=window_started,
                )
                with self._lock:
                    self._status.last_window_finished_at = _now_text()
                    self._status.last_pcap = str(file_path)
                    self._status.last_ready_pcap = result.ready_pcap
                    self._status.last_detected = result.detected
                    self._status.last_inserted = result.inserted
                    self._status.last_finalized_flows = result.finalized_flows
                    self._status.last_finalized_packets = result.finalized_packets
                    self._status.total_windows += 1
                    self._status.total_detected += result.detected
                    self._status.total_inserted += result.inserted
                    self._status.total_finalized_flows += result.finalized_flows
                    self._status.total_finalized_packets += result.finalized_packets
                    self._status.current_file = None
                    self._sync_cache_counts_locked()
                    self._status.message = (
                        f"窗口处理完成：本次处理 {result.finalized_flows} 条流/{result.finalized_packets} 个报文，"
                        f"检测 {result.detected} 条，入库 {result.inserted} 条；缓存 {self._status.cached_flows} 条流"
                    )
            except Exception as exc:  # pragma: no cover - depends on local capture privileges/tooling
                with self._lock:
                    self._status.last_error = str(exc)
                    self._status.current_file = None
                    self._status.message = f"在线监听异常：{exc}"
                if self._stop_event.wait(timeout=5):
                    break

        with self._lock:
            self._status.running = False
            self._status.current_file = None
            if self._status.message.startswith("正在采集"):
                self._status.message = "在线监听已停止"

    def _capture_one_window(self, interface: str, interval_sec: int, bpf_filter: str, file_path: Path) -> None:
        cmd = ["tcpdump", "-i", interface, "-s", "0", "-U", "-w", str(file_path)]
        if bpf_filter:
            cmd.extend(shlex.split(bpf_filter))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._proc = proc
        try:
            deadline = time.monotonic() + interval_sec
            while time.monotonic() < deadline:
                if self._stop_event.wait(timeout=0.25):
                    break
                if proc.poll() is not None:
                    break
            if proc.poll() is None:
                _terminate_process(proc)
            _, stderr = proc.communicate(timeout=5)
            if proc.returncode not in (0, -15, -2, 130, 143):
                err = stderr.decode("utf-8", errors="ignore").strip()
                raise RuntimeError(err or f"tcpdump 退出码 {proc.returncode}")
        finally:
            self._proc = None

    def _ingest_and_process_window(
        self,
        file_path: Path,
        idle_timeout_sec: int,
        flush_all: bool = False,
        window_started: datetime | None = None,
    ) -> _ProcessResult:
        if file_path.exists() and file_path.stat().st_size > 0:
            for packet in rdpcap(str(file_path)):
                self._cache_packet(packet)
        return self._process_ready_flows(
            idle_timeout_sec=idle_timeout_sec,
            flush_all=flush_all,
            window_started=window_started or datetime.now(),
        )

    def _cache_packet(self, packet: Packet) -> None:
        key = _flow_key(packet)
        if key is None:
            return
        pkt_ts = float(getattr(packet, "time", time.time()))
        cached_packet = packet.copy()
        cached_packet.time = pkt_ts
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = _CachedFlow(first_seen=pkt_ts, last_seen=pkt_ts)
                self._flows[key] = flow
            flow.packets.append(cached_packet)
            flow.last_seen = pkt_ts
            flow.close_seen = flow.close_seen or _has_fin_or_rst(packet)
            self._sync_cache_counts_locked()

    def _process_ready_flows(
        self,
        idle_timeout_sec: int,
        flush_all: bool = False,
        window_started: datetime | None = None,
    ) -> _ProcessResult:
        now = time.time()
        with self._lock:
            ready_keys = [
                key
                for key, flow in self._flows.items()
                if flush_all or flow.close_seen or (now - flow.last_seen) >= idle_timeout_sec
            ]
            ready_packets = [pkt for key in ready_keys for pkt in self._flows[key].packets]

        if not ready_packets:
            return _ProcessResult()

        ready_packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))
        ready_pcap = self._write_ready_pcap(ready_packets, len(ready_keys), window_started or datetime.now())
        detected, inserted = self._analyze_ready_pcap(ready_pcap)
        with self._lock:
            for key in ready_keys:
                self._flows.pop(key, None)
            self._sync_cache_counts_locked()
        return _ProcessResult(
            detected=detected,
            inserted=inserted,
            finalized_flows=len(ready_keys),
            finalized_packets=len(ready_packets),
            ready_pcap=str(ready_pcap),
        )

    def _write_ready_pcap(self, packets: list[Packet], flow_count: int, window_started: datetime) -> Path:
        stamp = window_started.strftime("%Y%m%d_%H%M%S_%f")
        file_path = self.output_dir / f"ready_flows_{stamp}_{flow_count}flows_{len(packets)}pkts.pcap"
        wrpcap(str(file_path), packets)
        return file_path

    def _analyze_ready_pcap(self, file_path: Path) -> tuple[int, int]:
        configs = list_self_hosted()
        entries = parse_pcap_to_entries(file_path, self_hosted_configs=configs)
        inserted = sum(1 for entry in entries if insert_entry(entry))
        return len(entries), inserted

    def _sync_cache_counts_locked(self) -> None:
        self._status.cached_flows = len(self._flows)
        self._status.cached_packets = sum(len(flow.packets) for flow in self._flows.values())


def _flow_key(packet: Packet) -> FlowKey | None:
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


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _now_text() -> str:
    return _format_dt(datetime.now())


def _format_dt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")
