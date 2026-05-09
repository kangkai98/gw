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

from .db import insert_entry, list_self_hosted
from .parser import parse_pcap_to_entries

CAPTURE_PATH = Path("captures")
CAPTURE_PATH.mkdir(exist_ok=True)


@dataclass
class CaptureStatus:
    running: bool = False
    interface: str = ""
    interval_sec: int = 60
    bpf_filter: str = "tcp"
    started_at: str | None = None
    current_file: str | None = None
    last_window_started_at: str | None = None
    last_window_finished_at: str | None = None
    last_pcap: str | None = None
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
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _status: CaptureStatus = field(default_factory=CaptureStatus, init=False)

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status.__dict__)

    def start(self, interface: str, interval_sec: int = 60, bpf_filter: str = "tcp") -> dict[str, Any]:
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("interface 不能为空")
        if shutil.which("tcpdump") is None:
            raise RuntimeError("未找到 tcpdump，请先安装 tcpdump 或在具备抓包能力的环境中运行")

        interval_sec = max(5, int(interval_sec or 60))
        bpf_filter = (bpf_filter or "tcp").strip() or "tcp"

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("在线监听已在运行")
            self._stop_event.clear()
            now = _now_text()
            self._status = CaptureStatus(
                running=True,
                interface=interface,
                interval_sec=interval_sec,
                bpf_filter=bpf_filter,
                started_at=now,
                message=f"在线监听已启动：{interface}，每 {interval_sec} 秒分析一次",
            )
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(interface, interval_sec, bpf_filter),
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

    def _run_loop(self, interface: str, interval_sec: int, bpf_filter: str) -> None:
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
                if self._stop_event.is_set() and (not file_path.exists() or file_path.stat().st_size == 0):
                    break
                detected, inserted = self._analyze_window(file_path)
                finished = _now_text()
                with self._lock:
                    self._status.last_window_finished_at = finished
                    self._status.last_pcap = str(file_path)
                    self._status.last_detected = detected
                    self._status.last_inserted = inserted
                    self._status.total_windows += 1
                    self._status.total_detected += detected
                    self._status.total_inserted += inserted
                    self._status.message = f"窗口分析完成：检测 {detected} 条，入库 {inserted} 条"
            except Exception as exc:  # pragma: no cover - depends on local capture privileges/tooling
                with self._lock:
                    self._status.last_error = str(exc)
                    self._status.message = f"在线监听异常：{exc}"
                # Avoid a tight retry loop when tcpdump fails immediately (e.g. no permission/interface not found).
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
            if proc.returncode not in (0, -15, -2, 143, 130):
                err = stderr.decode("utf-8", errors="ignore").strip()
                raise RuntimeError(err or f"tcpdump 退出码 {proc.returncode}")
        finally:
            self._proc = None

    def _analyze_window(self, file_path: Path) -> tuple[int, int]:
        if not file_path.exists() or file_path.stat().st_size == 0:
            return 0, 0
        configs = list_self_hosted()
        entries = parse_pcap_to_entries(file_path, self_hosted_configs=configs)
        inserted = sum(1 for entry in entries if insert_entry(entry))
        return len(entries), inserted


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
