from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
import platform
import multiprocessing
import queue as queue_module
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from scapy.all import IP, TCP, PcapReader
from scapy.utils import RawPcapReader, RawPcapWriter

from .db import insert_entry, insert_traffic_summary, list_self_hosted
from .parser import parse_pcap_to_entries, summarize_pcap_traffic, traffic_totals_lock

CAPTURE_PATH = Path("captures")
CAPTURE_PATH.mkdir(exist_ok=True)


def _parse_ready_pcap_worker(pcap_path: str, configs: list[dict], result_queue: Any) -> None:
    try:
        path = Path(pcap_path)
        with traffic_totals_lock:
            entries = parse_pcap_to_entries(path, self_hosted_configs=configs)
            traffic_summary = summarize_pcap_traffic(path, self_hosted_configs=configs)
        result_queue.put(("ok", entries, traffic_summary))
    except BaseException as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}", None))


def _parse_ready_pcap_in_process(
    pcap_path: Path, configs: list[dict], stop_event: threading.Event
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if "fork" not in multiprocessing.get_all_start_methods():
        with traffic_totals_lock:
            entries = parse_pcap_to_entries(pcap_path, self_hosted_configs=configs)
            traffic_summary = summarize_pcap_traffic(pcap_path, self_hosted_configs=configs)
        return entries, traffic_summary

    ctx = multiprocessing.get_context("fork")
    result_queue = ctx.Queue(maxsize=1)
    proc = ctx.Process(target=_parse_ready_pcap_worker, args=(str(pcap_path), configs, result_queue), daemon=True)
    proc.start()
    try:
        while True:
            if stop_event.is_set():
                proc.terminate()
                proc.join(timeout=2)
                raise RuntimeError("ready分析已因停止监听中断")
            try:
                status, entries, traffic_summary = result_queue.get(timeout=0.5)
                break
            except queue_module.Empty:
                if not proc.is_alive():
                    proc.join(timeout=0.5)
                    raise RuntimeError(f"ready分析子进程异常退出：{proc.exitcode}")
        proc.join(timeout=2)
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=2)
        result_queue.close()

    if status == "error":
        raise RuntimeError(entries)
    return entries, traffic_summary


@dataclass
class CachedTcpPacket:
    ts: float
    flow_key: str
    tcp_flags: int
    raw_packet: bytes
    cap_len: int
    wire_len: int
    link_type: int
    capture_seq: int


@dataclass
class CaptureStatus:
    running: bool = False
    interface: str = ""
    interval_sec: int = 60
    idle_timeout_sec: int = 120
    max_flow_duration_sec: int = 300
    pcap_retention_sec: int = 0
    bpf_filter: str = "tcp"
    capture_mode: str = "linux"
    started_at: str | None = None
    current_file: str | None = None
    last_window_started_at: str | None = None
    last_window_finished_at: str | None = None
    last_pcap: str | None = None
    last_analyzed_pcap: str | None = None
    cached_flows: int = 0
    cached_packets: int = 0
    last_ready_flows: int = 0
    last_deleted_pcaps: int = 0
    total_deleted_pcaps: int = 0
    last_detected: int = 0
    last_inserted: int = 0
    pending_online_windows: int = 0
    pending_online_files: int = 0
    total_capture_windows: int = 0
    total_online_files: int = 0
    total_windows: int = 0
    analyzed_online_files: int = 0
    total_ready_files: int = 0
    analyzed_ready_files: int = 0
    pending_ready_files: int = 0
    last_analysis_file: str | None = None
    last_analysis_file_size_bytes: int = 0
    last_analysis_duration_sec: float | None = None
    total_detected: int = 0
    total_inserted: int = 0
    last_error: str | None = None
    message: str = "未启动在线监听"


@dataclass
class OnlineCaptureManager:
    output_dir: Path = CAPTURE_PATH
    on_entry_inserted: Callable[[dict[str, Any]], None] | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _status: CaptureStatus = field(default_factory=CaptureStatus, init=False)
    _flow_cache: dict[str, list[CachedTcpPacket]] = field(default_factory=dict, init=False)
    _next_packet_seq: int = field(default=0, init=False)
    _capture_backend: str = field(default="", init=False)
    _run_started_at: float = field(default=0.0, init=False)
    _last_analyzed_pcap_size_bytes: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status.__dict__)

    def start(
        self,
        interface: str,
        preferred_backend: str = "",
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="linux",
        )

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if not any(shutil.which(cmd) for cmd in ("dumpcap", "tshark")):
                raise RuntimeError("未找到 dumpcap/tshark，请安装 Wireshark（含命令行工具）")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            self._capture_backend = backend
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_backend=backend,
                started_at=now,
                message=(
                    f"在线监听已启动（{mode}）：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if not any(shutil.which(cmd) for cmd in ("dumpcap", "tshark")):
                raise RuntimeError("未找到 dumpcap/tshark，请安装 Wireshark（含命令行工具）")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            self._run_started_at = time.time()
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                started_at=now,
                message=(
                    f"在线监听已启动：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if not any(shutil.which(cmd) for cmd in ("dumpcap", "tshark")):
                raise RuntimeError("未找到 dumpcap/tshark，请安装 Wireshark（含命令行工具）")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_mode=mode,
                started_at=now,
                message=(
                    f"在线监听已启动（{mode}）：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if not any(shutil.which(cmd) for cmd in ("dumpcap", "tshark")):
                raise RuntimeError("未找到 dumpcap/tshark，请安装 Wireshark（含命令行工具）")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_mode=mode,
                started_at=now,
                message=(
                    f"在线监听已启动（{mode}）：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if shutil.which("tshark") is None:
                raise RuntimeError("未找到 tshark，请安装 Wireshark 并将 tshark 加入 PATH")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_mode=mode,
                started_at=now,
                message=(
                    f"在线监听已启动（{mode}）：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if shutil.which("tshark") is None:
                raise RuntimeError("未找到 tshark，请安装 Wireshark 并将 tshark 加入 PATH")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_mode=mode,
                started_at=now,
                message=(
                    f"在线监听已启动：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def start_windows(
        self,
        interface: str,
        interval_sec: int = 60,
        bpf_filter: str = "tcp",
        idle_timeout_sec: int = 120,
        max_flow_duration_sec: int = 300,
        pcap_retention_sec: int = 0,
    ) -> dict[str, Any]:
        return self._start_with_mode(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
            mode="windows",
        )

    def _start_with_mode(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str,
    ) -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if mode == "windows":
            if shutil.which("tshark") is None:
                raise RuntimeError("未找到 tshark，请安装 Wireshark 并将 tshark 加入 PATH")
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"
        idle_timeout_sec = max(5, int(idle_timeout_sec or 120))
        max_flow_duration_sec = max(0, int(max_flow_duration_sec or 0))
        pcap_retention_sec = max(0, int(pcap_retention_sec or 0))

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            self._flow_cache.clear()
            self._next_packet_seq = 0
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                idle_timeout_sec=idle_timeout_sec,
                max_flow_duration_sec=max_flow_duration_sec,
                pcap_retention_sec=pcap_retention_sec,
                bpf_filter=bpf_filter,
                capture_mode=mode,
                started_at=now,
                message=(
                    f"在线监听已启动：{interface}，每 {interval_sec} 秒采集一次，"
                    f"空闲超时 {idle_timeout_sec} 秒，最长缓存 {max_flow_duration_sec or '不限'} 秒"
                ),
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, mode),
                name="ai-gateway-online-capture",
                daemon=True,
            )
            self._thread.start()
            return dict(self._status.__dict__)

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        proc = self._proc
        capture_mode = self._status.capture_mode
        if proc and proc.poll() is None and capture_mode != "windows":
            _terminate_process(proc)
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=8 if capture_mode == "windows" else 5)
        with self._lock:
            self._status.running = False
            self._status.message = "在线监听已停止"
            self._status.current_file = None
            return dict(self._status.__dict__)

    def _run_loop(
        self,
        interface: str,
        interval_sec: int,
        bpf_filter: str,
        idle_timeout_sec: int,
        max_flow_duration_sec: int,
        pcap_retention_sec: int,
        mode: str = "linux",
    ) -> None:
        processed_files: set[Path] = set()
        queued_files: set[Path] = set()
        pending_files: deque[Path] = deque()
        pending_lock = threading.Lock()
        pending_event = threading.Event()
        analyzer_done = threading.Event()

        ready_files: deque[Path] = deque()
        ready_queued: set[Path] = set()
        ready_lock = threading.Lock()
        ready_event = threading.Event()
        ready_done = threading.Event()

        def _enqueue_ready_file(ready_pcap: Path | None) -> None:
            if ready_pcap is None:
                return
            with ready_lock:
                if ready_pcap in ready_queued:
                    return
                ready_files.append(ready_pcap)
                ready_queued.add(ready_pcap)
                with self._lock:
                    self._status.pending_ready_files = len(ready_queued)
                ready_event.set()

        def _enqueue_rotated_files(finalize: bool) -> None:
            files = sorted(self.output_dir.glob("online*.pcap"), key=lambda p: p.name)
            candidates = files if finalize else files[:-1]
            with pending_lock:
                for file_path in candidates:
                    if file_path in processed_files or file_path in queued_files or not file_path.exists():
                        continue
                    try:
                        if file_path.stat().st_mtime + 1e-6 < self._run_started_at:
                            continue
                    except OSError:
                        continue
                    pending_files.append(file_path)
                    queued_files.add(file_path)
                    with self._lock:
                        self._status.total_capture_windows += 1
                        self._status.total_online_files = self._status.total_capture_windows
                        self._status.pending_online_windows = len(queued_files)
                        self._status.pending_online_files = len(queued_files)
                if pending_files:
                    pending_event.set()

        def _analyze_worker() -> None:
            while True:
                pending_event.wait(timeout=0.5)
                file_path: Path | None = None
                with pending_lock:
                    if pending_files:
                        file_path = pending_files.popleft()
                    else:
                        pending_event.clear()
                if file_path is None:
                    if analyzer_done.is_set():
                        break
                    continue
                try:
                    ready_pcap = self._process_rotated_file(
                        file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec
                    )
                    _enqueue_ready_file(ready_pcap)
                except Exception as exc:  # pragma: no cover - depends on local pcap/parser state
                    with self._lock:
                        self._status.last_error = str(exc)
                        self._status.message = f"在线监听online处理异常：{exc}"
                finally:
                    with pending_lock:
                        queued_files.discard(file_path)
                        processed_files.add(file_path)
                        with self._lock:
                            self._status.pending_online_windows = len(queued_files)
                            self._status.pending_online_files = len(queued_files)

        def _ready_worker() -> None:
            while True:
                ready_event.wait(timeout=0.5)
                if ready_done.is_set() and self._stop_event.is_set():
                    break
                ready_pcap: Path | None = None
                with ready_lock:
                    if ready_files:
                        ready_pcap = ready_files.popleft()
                    else:
                        ready_event.clear()
                if ready_pcap is None:
                    if ready_done.is_set():
                        break
                    continue
                try:
                    self._process_ready_file(ready_pcap, pcap_retention_sec)
                except Exception as exc:  # pragma: no cover - depends on parser/db state
                    with self._lock:
                        self._status.last_error = str(exc)
                        self._status.message = f"在线监听ready分析异常：{exc}"
                finally:
                    with ready_lock:
                        ready_queued.discard(ready_pcap)
                        with self._lock:
                            self._status.pending_ready_files = len(ready_queued)

        analyzer = threading.Thread(target=_analyze_worker, name="ai-gateway-online-ingest", daemon=True)
        ready_analyzer = threading.Thread(target=_ready_worker, name="ai-gateway-ready-analyze", daemon=True)
        analyzer.start()
        ready_analyzer.start()
        proc = self._start_continuous_capture(interface, interval_sec, bpf_filter, mode=mode)
        self._proc = proc
        try:
            while not self._stop_event.is_set():
                _enqueue_rotated_files(finalize=False)
                if proc.poll() is not None:
                    _, stderr = proc.communicate(timeout=5)
                    if proc.returncode not in (0, -15, -2, 143, 130, 1):
                        err = stderr.decode("utf-8", errors="ignore").strip()
                        tool_name = "tshark" if mode == "windows" else "tcpdump"
                        raise RuntimeError(err or f"{tool_name} 退出码 {proc.returncode}")
                    break
                with self._lock:
                    pending_count = len(queued_files)
                    self._status.pending_online_windows = pending_count
                    self._status.pending_online_files = pending_count
                    self._status.current_file = "rolling"
                    self._status.message = (
                        f"正在采集：每 {interval_sec} 秒生成 online 文件，"
                        f"online 已生成 {self._status.total_online_files} 个，"
                        f"已处理 {self._status.analyzed_online_files} 个，待处理 {pending_count} 个；"
                        f"ready 已生成 {self._status.total_ready_files} 个，"
                        f"已分析 {self._status.analyzed_ready_files} 个，待分析 {self._status.pending_ready_files} 个"
                    )
                if self._stop_event.wait(timeout=1):
                    break
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self._status.last_error = str(exc)
                self._status.message = f"在线监听异常：{exc}"
        finally:
            if proc.poll() is None:
                _terminate_process(proc)
            _enqueue_rotated_files(finalize=True)
            analyzer_done.set()
            pending_event.set()
            analyzer.join(timeout=10)
            ready_done.set()
            ready_event.set()
            ready_analyzer.join(timeout=1)
            self._proc = None

        with self._lock:
            self._status.running = False
            self._status.current_file = None
            if self._status.message.startswith("正在采集"):
                self._status.message = "在线监听已停止"

    def _start_continuous_capture(self, interface: str, interval_sec: int, bpf_filter: str, mode: str) -> subprocess.Popen[bytes]:
        if mode == "windows":
            if shutil.which("tshark") is None:
                raise RuntimeError("未找到 tshark，请安装 Wireshark 并将 tshark 加入 PATH")
            base_file = self.output_dir / "online.pcap"
            cmd = ["tshark", "-i", interface, "-F", "pcap", "-b", f"duration:{interval_sec}", "-w", str(base_file)]
            if bpf_filter:
                cmd.extend(["-f", bpf_filter])
        else:
            if shutil.which("tcpdump") is None:
                raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")
            pattern = self.output_dir / "online_%Y%m%d_%H%M%S.pcap"
            cmd = ["tcpdump", "-i", interface, "-s", "0", "-G", str(interval_sec), "-w", str(pattern)]
            if bpf_filter:
                cmd.extend(shlex.split(bpf_filter))
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _process_rotated_file(
        self, file_path: Path, idle_timeout_sec: int, max_flow_duration_sec: int, pcap_retention_sec: int
    ) -> Path | None:
        analysis_started = time.perf_counter()
        detected, inserted, ready_flows, analyzed_pcap, deleted_pcaps = self._dispatch_analyze_window(
            file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec
        )
        analysis_duration_sec = time.perf_counter() - analysis_started
        finished = _now_text()
        with self._lock:
            self._status.last_window_finished_at = finished
            self._status.last_pcap = str(file_path)
            self._status.last_detected = detected
            self._status.last_analyzed_pcap = str(analyzed_pcap) if analyzed_pcap else None
            self._status.last_ready_flows = ready_flows
            self._status.last_inserted = inserted
            self._status.last_deleted_pcaps = deleted_pcaps
            self._status.total_deleted_pcaps += deleted_pcaps
            self._status.total_windows += 1
            self._status.analyzed_online_files = self._status.total_windows
            self._status.last_analysis_duration_sec = round(analysis_duration_sec, 3)
            self._refresh_cache_status_locked()
        return analyzed_pcap

    def _process_ready_file(self, analyzed_pcap: Path, pcap_retention_sec: int) -> None:
        analysis_started = time.perf_counter()
        configs = list_self_hosted()
        entries, traffic_summary = _parse_ready_pcap_in_process(analyzed_pcap, configs, self._stop_event)
        insert_traffic_summary({**traffic_summary, "source": "online"})
        inserted = 0
        for entry in entries:
            if not insert_entry(entry):
                continue
            inserted += 1
            if self.on_entry_inserted:
                try:
                    self.on_entry_inserted(entry)
                except Exception:
                    pass
        analysis_duration_sec = time.perf_counter() - analysis_started
        analysis_file_size = 0
        try:
            analysis_file_size = analyzed_pcap.stat().st_size if analyzed_pcap.exists() else 0
        except OSError:
            analysis_file_size = 0
        if analysis_file_size == 0:
            analysis_file_size = self._last_analyzed_pcap_size_bytes
        deleted_pcaps = 0
        if pcap_retention_sec == 0 and _delete_file(analyzed_pcap):
            deleted_pcaps += 1
        deleted_pcaps += _cleanup_expired_pcaps(
            self.output_dir,
            pcap_retention_sec,
            keep_latest_online=self._proc is not None and self._proc.poll() is None,
        )
        finished = _now_text()
        with self._lock:
            self._status.last_window_finished_at = finished
            self._status.last_detected = len(entries)
            self._status.last_inserted = inserted
            self._status.last_analyzed_pcap = str(analyzed_pcap)
            self._status.last_analysis_file = str(analyzed_pcap)
            self._status.last_analysis_file_size_bytes = analysis_file_size
            self._status.last_analysis_duration_sec = round(analysis_duration_sec, 3)
            self._status.last_deleted_pcaps = deleted_pcaps
            self._status.total_deleted_pcaps += deleted_pcaps
            self._status.total_detected += len(entries)
            self._status.total_inserted += inserted
            self._status.analyzed_ready_files += 1

    def _capture_one_window(self, interface: str, interval_sec: int, bpf_filter: str, file_path: Path, mode: str = "linux") -> None:
        if mode == "windows":
            if shutil.which("tshark"):
                cmd = ["tshark", "-i", interface, "-a", f"duration:{interval_sec}", "-F", "pcap", "-w", str(file_path)]
                if bpf_filter:
                    cmd.extend(["-f", bpf_filter])
            else:
                raise RuntimeError("未找到 tshark，请安装 Wireshark 并将 tshark 加入 PATH")
        else:
            cmd = ["tcpdump", "-i", interface, "-s", "0", "-U", "-w", str(file_path)]
            if bpf_filter:
                cmd.extend(shlex.split(bpf_filter))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._proc = proc
        try:
            if mode == "windows":
                graceful_deadline = time.monotonic() + max(interval_sec + 2, 3)
                while proc.poll() is None:
                    if self._stop_event.is_set():
                        # On Windows, force-terminating tshark may leave a truncated pcapng/pcap file.
                        # Prefer waiting for the current duration window to end naturally.
                        if time.monotonic() >= graceful_deadline:
                            _terminate_process(proc)
                            break
                        time.sleep(0.25)
                        continue
                    time.sleep(0.25)
            else:
                deadline = time.monotonic() + interval_sec
                while time.monotonic() < deadline:
                    if self._stop_event.wait(timeout=0.25):
                        break
                    if proc.poll() is not None:
                        break
                if proc.poll() is None:
                    _terminate_process(proc)
            _, stderr = proc.communicate(timeout=5)
            if proc.returncode not in (0, -15, -2, 143, 130, 1):
                err = stderr.decode("utf-8", errors="ignore").strip()
                tool_name = "tshark" if mode == "windows" else "tcpdump"
                raise RuntimeError(err or f"{tool_name} 退出码 {proc.returncode}")
        finally:
            self._proc = None

    def _dispatch_analyze_window(
        self, file_path: Path, idle_timeout_sec: int, max_flow_duration_sec: int, pcap_retention_sec: int
    ) -> tuple[int, int, int, Path | None, int]:
        """
        兼容分支合并导致的方法命名差异：
        - 新实现：_analyze_window(...)
        - 旧实现：analyze_window(...)
        """
        private_impl = getattr(self, "_analyze_window", None)
        if callable(private_impl):
            return private_impl(file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec)
        public_impl = getattr(self, "analyze_window", None)
        if callable(public_impl):
            return public_impl(file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec)
        raise RuntimeError("在线监听内部错误：缺少 analyze_window，请更新服务到最新版本")

    def analyze_window(
        self, file_path: Path, idle_timeout_sec: int, max_flow_duration_sec: int, pcap_retention_sec: int
    ) -> tuple[int, int, int, Path | None, int]:
        return self._analyze_window(file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec)

    def _analyze_window(
        self, file_path: Path, idle_timeout_sec: int, max_flow_duration_sec: int, pcap_retention_sec: int
    ) -> tuple[int, int, int, Path | None, int]:
        deleted_pcaps = 0
        packets: list[CachedTcpPacket] = []
        if file_path.exists():
            if file_path.stat().st_size > 0:
                packets = _extract_cached_tcp_packets(file_path, start_seq=self._next_packet_seq)
                self._next_packet_seq += len(packets)
                for flow_key, flow_packets in _group_cached_flows(packets).items():
                    cached = self._flow_cache.setdefault(flow_key, [])
                    cached.extend(flow_packets)
                    cached.sort(key=lambda p: p.capture_seq)
            if pcap_retention_sec == 0 and _delete_file(file_path):
                deleted_pcaps += 1

        observation_ts = max((p.ts for p in packets), default=time.time())
        ready_keys = self._ready_flow_keys(observation_ts, idle_timeout_sec, max_flow_duration_sec)
        ready_packets = [pkt for key in ready_keys for pkt in self._flow_cache.get(key, [])]
        analyzed_pcap = _ready_pcap_path(self.output_dir, observation_ts, file_path)
        _write_cached_packets_to_pcap(analyzed_pcap, ready_packets)
        try:
            self._last_analyzed_pcap_size_bytes = analyzed_pcap.stat().st_size
        except OSError:
            self._last_analyzed_pcap_size_bytes = 0
        with self._lock:
            self._status.total_ready_files += 1

        for key in ready_keys:
            self._flow_cache.pop(key, None)
        deleted_pcaps += _cleanup_expired_pcaps(
            self.output_dir,
            pcap_retention_sec,
            keep_latest_online=self._proc is not None and self._proc.poll() is None,
        )
        with self._lock:
            self._refresh_cache_status_locked()
        return 0, 0, len(ready_keys), analyzed_pcap, deleted_pcaps

    def _ready_flow_keys(
        self, observation_ts: float, idle_timeout_sec: int, max_flow_duration_sec: int
    ) -> list[str]:
        ready: list[str] = []
        for flow_key, packets in self._flow_cache.items():
            if not packets:
                ready.append(flow_key)
                continue
            first_seen = min(pkt.ts for pkt in packets)
            last_seen = max(pkt.ts for pkt in packets)
            has_fin_or_rst = any(pkt.tcp_flags & 0x05 for pkt in packets)
            is_idle = (observation_ts - last_seen) >= idle_timeout_sec
            is_too_old = max_flow_duration_sec > 0 and (observation_ts - first_seen) >= max_flow_duration_sec
            if has_fin_or_rst or is_idle or is_too_old:
                ready.append(flow_key)
        return ready

    def _refresh_cache_status_locked(self) -> None:
        self._status.cached_flows = len(self._flow_cache)
        self._status.cached_packets = sum(len(packets) for packets in self._flow_cache.values())


def _resolve_windows_interface(interface: str) -> str:
    raw = (interface or "").strip()
    if not raw:
        return raw
    if raw.isdigit():
        return raw
    try:
        proc = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=6,
            check=False,
        )
    except Exception:
        return raw
    output = proc.stdout or ""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    for line in lines:
        if ". " not in line:
            continue
        idx, rest = line.split(". ", 1)
        if not idx.isdigit():
            continue
        lower = rest.lower()
        if raw.lower() == rest.lower() or raw.lower() in lower:
            return idx
    return raw


def _extract_cached_tcp_packets(pcap_path: Path, start_seq: int = 0) -> list[CachedTcpPacket]:
    result: list[CachedTcpPacket] = []
    try:
        reader = RawPcapReader(str(pcap_path))
    except Exception:
        return _extract_cached_tcp_packets_scapy(pcap_path, start_seq)
    try:
        if getattr(reader, "linktype", None) != 1:
            reader.close()
            return _extract_cached_tcp_packets_scapy(pcap_path, start_seq)
        for raw_packet, meta in reader:
            tcp_meta = _extract_ipv4_tcp_meta_from_ethernet(raw_packet)
            if tcp_meta is None:
                continue
            src, sport, dst, dport, tcp_flags = tcp_meta
            result.append(
                CachedTcpPacket(
                    ts=float(meta.sec) + float(meta.usec) / 1_000_000,
                    flow_key=_canonical_flow_key(src, sport, dst, dport),
                    tcp_flags=tcp_flags,
                    raw_packet=bytes(raw_packet),
                    cap_len=int(meta.caplen),
                    wire_len=int(meta.wirelen),
                    link_type=int(getattr(reader, "linktype", 1) or 1),
                    capture_seq=start_seq + len(result),
                )
            )
    finally:
        try:
            reader.close()
        except Exception:
            pass
    return result


def _extract_cached_tcp_packets_scapy(pcap_path: Path, start_seq: int = 0) -> list[CachedTcpPacket]:
    result: list[CachedTcpPacket] = []
    with PcapReader(str(pcap_path)) as reader:
        link_type = int(getattr(reader, "linktype", 1) or 1)
        for packet in reader:
            if IP not in packet or TCP not in packet:
                continue
            ip = packet[IP]
            tcp = packet[TCP]
            raw_packet = bytes(packet)
            result.append(
                CachedTcpPacket(
                    ts=float(packet.time),
                    flow_key=_canonical_flow_key(str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport)),
                    tcp_flags=int(tcp.flags),
                    raw_packet=raw_packet,
                    cap_len=len(raw_packet),
                    wire_len=int(getattr(packet, "wirelen", len(raw_packet)) or len(raw_packet)),
                    link_type=link_type,
                    capture_seq=start_seq + len(result),
                )
            )
    return result


def _extract_ipv4_tcp_meta_from_ethernet(raw_packet: bytes) -> tuple[str, int, str, int, int] | None:
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
    fragment = int.from_bytes(raw_packet[ip_offset + 6 : ip_offset + 8], "big")
    if fragment & 0x1FFF:
        return None
    tcp_offset = ip_offset + ihl
    if len(raw_packet) < tcp_offset + 14:
        return None
    src = ".".join(str(part) for part in raw_packet[ip_offset + 12 : ip_offset + 16])
    dst = ".".join(str(part) for part in raw_packet[ip_offset + 16 : ip_offset + 20])
    sport = int.from_bytes(raw_packet[tcp_offset : tcp_offset + 2], "big")
    dport = int.from_bytes(raw_packet[tcp_offset + 2 : tcp_offset + 4], "big")
    tcp_flags = raw_packet[tcp_offset + 13]
    return src, sport, dst, dport, tcp_flags


def _group_cached_flows(packets: list[CachedTcpPacket]) -> dict[str, list[CachedTcpPacket]]:
    groups: dict[str, list[CachedTcpPacket]] = defaultdict(list)
    for packet in packets:
        groups[packet.flow_key].append(packet)
    return groups


def _canonical_flow_key(src: str, sport: int, dst: str, dport: int) -> str:
    left = (src, str(sport))
    right = (dst, str(dport))
    side1 = f"{left[0]}:{left[1]}"
    side2 = f"{right[0]}:{right[1]}"
    return f"{side1}-{side2}" if left <= right else f"{side2}-{side1}"


def _write_cached_packets_to_pcap(pcap_path: Path, packets: list[CachedTcpPacket]) -> None:
    ordered = sorted(packets, key=lambda x: x.capture_seq)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    link_type = ordered[0].link_type if ordered else 1
    writer = RawPcapWriter(str(pcap_path), linktype=link_type, sync=True)
    writer.write_header(None)
    try:
        for cached in ordered:
            sec = int(cached.ts)
            usec = int(round((cached.ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            writer.write_packet(
                cached.raw_packet,
                sec=sec,
                usec=usec,
                caplen=cached.cap_len,
                wirelen=cached.wire_len,
            )
    finally:
        writer.close()


def _ready_pcap_path(output_dir: Path, observation_ts: float, source_path: Path) -> Path:
    timestamp = datetime.fromtimestamp(observation_ts).strftime("%Y%m%d_%H%M%S")
    source_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in source_path.stem)
    base = output_dir / f"ready_{timestamp}_{source_stem}.pcap"
    if not base.exists():
        return base
    suffix = 1
    while True:
        candidate = output_dir / f"ready_{timestamp}_{source_stem}_{suffix}.pcap"
        if not candidate.exists():
            return candidate
        suffix += 1


def _cleanup_expired_pcaps(output_dir: Path, retention_sec: int, keep_latest_online: bool = False) -> int:
    if retention_sec <= 0:
        return 0
    cutoff = time.time() - retention_sec
    deleted = 0
    for pattern in ("online*.pcap", "ready_*.pcap"):
        paths = sorted(output_dir.glob(pattern), key=lambda p: p.stat().st_mtime if p.exists() else 0)
        if pattern == "online*.pcap" and keep_latest_online and paths:
            paths = paths[:-1]
        for path in paths:
            try:
                if path.stat().st_mtime <= cutoff and _delete_file(path):
                    deleted += 1
            except OSError:
                continue
    return deleted


def _delete_file(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


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
