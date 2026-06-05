from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
import platform
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from scapy.all import IP, TCP, PcapReader, wrpcap

from .db import insert_entry, insert_traffic_summary, list_self_hosted
from .parser import parse_pcap_to_entries, summarize_pcap_traffic, traffic_totals_lock

CAPTURE_PATH = Path("captures")
CAPTURE_PATH.mkdir(exist_ok=True)


@dataclass
class CachedTcpPacket:
    ts: float
    flow_key: str
    tcp_flags: int
    packet: Any
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
    total_windows: int = 0
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
        if proc and proc.poll() is None:
            _terminate_process(proc)
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5)
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
        proc = self._start_continuous_capture(interface, interval_sec, bpf_filter, mode=mode)
        self._proc = proc
        try:
            while not self._stop_event.is_set():
                self._drain_rotated_files(
                    processed_files, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, finalize=False
                )
                if proc.poll() is not None:
                    _, stderr = proc.communicate(timeout=5)
                    if proc.returncode not in (0, -15, -2, 143, 130, 1):
                        err = stderr.decode("utf-8", errors="ignore").strip()
                        tool_name = "tshark" if mode == "windows" else "tcpdump"
                        raise RuntimeError(err or f"{tool_name} 退出码 {proc.returncode}")
                    break
                with self._lock:
                    self._status.current_file = "rolling"
                    self._status.message = f"正在采集窗口：每 {interval_sec} 秒滚动写文件"
                if self._stop_event.wait(timeout=1):
                    break
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self._status.last_error = str(exc)
                self._status.message = f"在线监听异常：{exc}"
        finally:
            if proc.poll() is None:
                _terminate_process(proc)
            self._drain_rotated_files(processed_files, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec, finalize=True)
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

    def _drain_rotated_files(
        self, processed_files: set[Path], idle_timeout_sec: int, max_flow_duration_sec: int, pcap_retention_sec: int, finalize: bool
    ) -> None:
        files = sorted(self.output_dir.glob("online*.pcap"), key=lambda p: p.name)
        if not files:
            return
        candidates = files if finalize else files[:-1]
        for file_path in candidates:
            if file_path in processed_files or not file_path.exists():
                continue
            try:
                if file_path.stat().st_mtime + 1e-6 < self._run_started_at:
                    continue
            except OSError:
                continue
            detected, inserted, ready_flows, analyzed_pcap, deleted_pcaps = self._dispatch_analyze_window(
                file_path, idle_timeout_sec, max_flow_duration_sec, pcap_retention_sec
            )
            processed_files.add(file_path)
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
                self._status.total_detected += detected
                self._status.total_inserted += inserted
                self._refresh_cache_status_locked()

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
        if not ready_keys:
            with self._lock:
                self._refresh_cache_status_locked()
            deleted_pcaps += _cleanup_expired_pcaps(self.output_dir, pcap_retention_sec)
            return 0, 0, 0, None, deleted_pcaps

        ready_packets = [pkt for key in ready_keys for pkt in self._flow_cache.get(key, [])]
        analyzed_pcap = self.output_dir / f"ready_{datetime.fromtimestamp(observation_ts).strftime('%Y%m%d_%H%M%S')}.pcap"
        _write_cached_packets_to_pcap(analyzed_pcap, ready_packets)

        configs = list_self_hosted()
        with traffic_totals_lock:
            entries = parse_pcap_to_entries(analyzed_pcap, self_hosted_configs=configs)
            traffic_summary = summarize_pcap_traffic(analyzed_pcap, self_hosted_configs=configs)
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

        for key in ready_keys:
            self._flow_cache.pop(key, None)
        if pcap_retention_sec == 0 and _delete_file(analyzed_pcap):
            deleted_pcaps += 1
        deleted_pcaps += _cleanup_expired_pcaps(self.output_dir, pcap_retention_sec)
        with self._lock:
            self._refresh_cache_status_locked()
        return len(entries), inserted, len(ready_keys), analyzed_pcap, deleted_pcaps

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
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP not in packet or TCP not in packet:
                continue
            ip = packet[IP]
            tcp = packet[TCP]
            result.append(
                CachedTcpPacket(
                    ts=float(packet.time),
                    flow_key=_canonical_flow_key(str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport)),
                    tcp_flags=int(tcp.flags),
                    packet=packet.copy(),
                    capture_seq=start_seq + len(result),
                )
            )
    return result


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
    scapy_packets = []
    for cached in ordered:
        packet = cached.packet.copy()
        packet.time = cached.ts
        scapy_packets.append(packet)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(pcap_path), scapy_packets)


def _cleanup_expired_pcaps(output_dir: Path, retention_sec: int) -> int:
    if retention_sec <= 0:
        return 0
    cutoff = time.time() - retention_sec
    deleted = 0
    for pattern in ("online_*.pcap", "ready_*.pcap"):
        for path in output_dir.glob(pattern):
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
